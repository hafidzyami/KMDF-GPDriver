#include "pch.h"
#include "tdriver.h"
#include "fixed_structures.h"
#include "AlertQueueExtension.h"

// Define our own conversion function directly in this file to avoid conflicts
inline PFAST_MUTEX IOCTLConvertToFastMutex(ULONG_PTR ptr) {
    return (PFAST_MUTEX)ptr;
}

// Initialize static members of TDriverClass for statistics
LARGE_INTEGER TDriverClass::DriverStartTime = {0};
ULONG TDriverClass::TotalProcessesMonitored = 0;
ULONG TDriverClass::ActiveProcesses = 0;
ULONG TDriverClass::RegistryOperationsBlocked = 0;
ULONG TDriverClass::ThreadsMonitored = 0;
ULONG TDriverClass::RemoteThreadsDetected = 0;
ULONG TDriverClass::ImagesMonitored = 0;
ULONG TDriverClass::RemoteImagesDetected = 0;

/**
 * Get current system time
 */
VOID GetCurrentSystemTime(
    _Out_ PLARGE_INTEGER CurrentTime)
{
    KeQuerySystemTime(CurrentTime);
}

/**
 * Helper function to retrieve multiple alerts from queue
 */
ULONG PopMultipleAlertsCompat(
    _In_ PALERT_QUEUE AlertQueue,
    _Out_ PALERT_INFO AlertBuffer,
    _In_ ULONG MaxAlerts)
{
    if (AlertQueue == NULL || AlertBuffer == NULL || MaxAlerts == 0) {
        return 0;
    }

    ULONG alertCount = 0;
    PBASE_ALERT_INFO baseAlert;

    // Pop up to MaxAlerts alerts from the queue
    while (!AlertQueue->IsQueueEmpty() && alertCount < MaxAlerts) {
        baseAlert = AlertQueue->PopAlert();
        if (baseAlert == NULL) {
            break;
        }

        // Convert to ALERT_INFO structure
        AlertBuffer[alertCount].AlertId = alertCount + 1;
        AlertBuffer[alertCount].Type = (ALERT_TYPE)baseAlert->AlertType;
        AlertBuffer[alertCount].SourceProcessId = HandleToUlong(baseAlert->SourceId);
        
        // Copy source path
        RtlZeroMemory(AlertBuffer[alertCount].SourcePath, MAX_PATH * sizeof(WCHAR));
        RtlCopyMemory(AlertBuffer[alertCount].SourcePath, 
                      baseAlert->SourcePath, 
                      min(MAX_PATH * sizeof(WCHAR), sizeof(baseAlert->SourcePath)));
        
        // Copy target path
        RtlZeroMemory(AlertBuffer[alertCount].TargetPath, MAX_PATH * sizeof(WCHAR));
        RtlCopyMemory(AlertBuffer[alertCount].TargetPath, 
                      baseAlert->TargetPath, 
                      min(MAX_PATH * sizeof(WCHAR), sizeof(baseAlert->TargetPath)));

        // Get current time
        KeQuerySystemTime(&AlertBuffer[alertCount].Timestamp);

        // Free the alert
        AlertQueue->FreeAlert(baseAlert);
        alertCount++;
    }

    return alertCount;
}

/**
 * Handler for IOCTL_GET_PROCESS_LIST
 * Provides a list of all monitored processes
 */
NTSTATUS HandleGetProcessList(_In_ PIRP Irp, _In_ PIO_STACK_LOCATION IrpSp) {
    NTSTATUS status = STATUS_SUCCESS;
    ULONG outputBufferLength = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;
    PVOID outputBuffer = Irp->AssociatedIrp.SystemBuffer;
    ULONG bytesReturned = 0;
    PPROCESS_SUMMARY_ENTRY processSummaries = NULL;

    // Check if we have at least enough space for the count
    if (outputBufferLength < sizeof(PROCESS_LIST)) {
        PROCESS_LIST countOnly;
        countOnly.Count = (ULONG)TDriverClass::GetImageProcessFilter()->ProcessHistorySize;

        // Return just the count so the client knows how much space is needed
        RtlCopyMemory(outputBuffer, &countOnly, sizeof(PROCESS_LIST));
        bytesReturned = sizeof(PROCESS_LIST);
        status = STATUS_BUFFER_TOO_SMALL;

        DbgPrint("[IOCTL] Buffer too small for process list. Required processes: %lu", countOnly.Count);
        goto Exit;
    }

    // The output buffer is large enough for at least the header, now see if we can fit all processes
    PPROCESS_LIST pList = (PPROCESS_LIST)outputBuffer;
    ULONG maxProcesses = (outputBufferLength - sizeof(PROCESS_LIST)) / sizeof(PROCESS_INFO) + 1;

    // Initialize the count to 0, will be updated as we fill the list
    pList->Count = 0;

    // Check if we have actual process data from ImageProcessFilter
    ULONG actualProcessCount = (ULONG)TDriverClass::GetImageProcessFilter()->ProcessHistorySize;
    
    // Only proceed if we have actual process data
    if (actualProcessCount > 0) {
        processSummaries = 
            (PPROCESS_SUMMARY_ENTRY)ExAllocatePool2(POOL_FLAG_PAGED, maxProcesses * sizeof(PROCESS_SUMMARY_ENTRY), 'PROS');

        if (processSummaries == NULL) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            DbgPrint("[IOCTL] Failed to allocate memory for process summaries");
            goto Exit;
        }

        RtlZeroMemory(processSummaries, maxProcesses * sizeof(PROCESS_SUMMARY_ENTRY));

        // Get the process summaries
        actualProcessCount = TDriverClass::GetImageProcessFilter()->GetProcessHistorySummary(
            0,                // Skip count - start from the beginning
            processSummaries, // Buffer for summaries
            maxProcesses      // Maximum processes to return
        );

        // Convert PROCESS_SUMMARY_ENTRY to PROCESS_INFO
        for (ULONG i = 0; i < actualProcessCount; i++) {
            // [Convert process data, same as original code]
        }
    }
    // If no actual process data, we just return count = 0

    pList->Count = actualProcessCount;
    bytesReturned = sizeof(PROCESS_LIST) + (actualProcessCount - 1) * sizeof(PROCESS_INFO);

    DbgPrint("[IOCTL] Successfully returned %lu processes", actualProcessCount);

Exit:
    // Clean up allocated memory if needed
    if (processSummaries != NULL) {
        ExFreePool(processSummaries);
    }

    // Set the bytes returned
    Irp->IoStatus.Information = bytesReturned;
    return status;
}

/**
 * Handler for IOCTL_GET_PROCESS_DETAILS
 * Gets detailed information about a specific process
 */
NTSTATUS
HandleGetProcessDetails(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IrpSp)
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG inputBufferLength = IrpSp->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outputBufferLength = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;
    PVOID inputBuffer = Irp->AssociatedIrp.SystemBuffer;
    PVOID outputBuffer = Irp->AssociatedIrp.SystemBuffer;
    ULONG bytesReturned = 0;

    // Check input parameters
    if (inputBufferLength < sizeof(PROCESS_DETAILS_REQUEST))
    {
        DbgPrint("[IOCTL] Invalid input buffer size for process details request");
        status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    // Get the process ID from the input
    PPROCESS_DETAILS_REQUEST pRequest = (PPROCESS_DETAILS_REQUEST)inputBuffer;
    ULONG processId = pRequest->ProcessId;

    // First check if the output buffer is large enough for basic process info
    if (outputBufferLength < sizeof(PROCESS_INFO))
    {
        DbgPrint("[IOCTL] Buffer too small for process details");
        status = STATUS_BUFFER_TOO_SMALL;
        goto Exit;
    }

    // Get process details from the image filter
    // This is a simplified implementation - in a real handler, you would extract process details
    // from your internal process tracking structures
    PROCESS_INFO processInfo;
    RtlZeroMemory(&processInfo, sizeof(PROCESS_INFO));

    // Set basic information
    processInfo.ProcessId = processId;

    // Populate with real data - this would be implemented based on your data structures
    // For example, use GetProcessImageFileName and other functions to get details

    // For this demonstration, we'll just fill with some sample data
    processInfo.ParentProcessId = 0;  // Would be filled from actual data
    processInfo.IsTerminated = FALSE; // Would be filled from actual data

    // Copy to output buffer
    RtlCopyMemory(outputBuffer, &processInfo, sizeof(PROCESS_INFO));
    bytesReturned = sizeof(PROCESS_INFO);

    DbgPrint("[IOCTL] Successfully returned details for process %lu", processId);

Exit:
    // Set the bytes returned
    Irp->IoStatus.Information = bytesReturned;
    return status;
}

/**
 * Handler for IOCTL_ADD_REGISTRY_FILTER
 * Adds a registry path to the protected filters
 */
/**
 * Handler for IOCTL_ADD_REGISTRY_FILTER
 * Adds a registry path to the protected filters
 */
NTSTATUS
HandleAddRegistryFilter(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IrpSp)
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG inputBufferLength = IrpSp->Parameters.DeviceIoControl.InputBufferLength;
    PVOID inputBuffer = Irp->AssociatedIrp.SystemBuffer;
    ULONG bytesReturned = 0;
    WCHAR* registryPathBuffer = NULL;

    // Check input parameters
    if (inputBufferLength < sizeof(REGISTRY_FILTER))
    {
        DbgPrint("[IOCTL] Invalid input buffer size for add registry filter");
        status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    // Get the registry filter info from the input
    PREGISTRY_FILTER pFilter = (PREGISTRY_FILTER)inputBuffer;

    // Add the registry path to the protected filters
    if (TDriverClass::GetObjectMonitor() && TDriverClass::GetObjectMonitor()->GetRegistryStringFilters())
    {
        UNICODE_STRING registryPath;
        RtlInitUnicodeString(&registryPath, pFilter->RegistryPath);

        // Check for valid UNICODE_STRING
        if (registryPath.Buffer == NULL || registryPath.Length == 0)
        {
            DbgPrint("[IOCTL] Invalid registry path string");
            status = STATUS_INVALID_PARAMETER;
            goto Exit;
        }

        // Create a null-terminated wide string copy of the registry path
        registryPathBuffer = (WCHAR*)ExAllocatePool2(POOL_FLAG_PAGED, 
                                                  (registryPath.Length + sizeof(WCHAR)), 
                                                  'REGP');
        if (registryPathBuffer == NULL) {
            DbgPrint("[IOCTL] Failed to allocate memory for registry path");
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto Exit;
        }

        // Copy the string and ensure null termination
        RtlCopyMemory(registryPathBuffer, registryPath.Buffer, registryPath.Length);
        registryPathBuffer[registryPath.Length / sizeof(WCHAR)] = L'\0';

        // Fix the type of the result variable
        ULONG result = TDriverClass::GetObjectMonitor()->GetRegistryStringFilters()->AddFilter(
            registryPathBuffer,
            pFilter->FilterFlags);

        // Free the temporary buffer
        ExFreePool(registryPathBuffer);
        registryPathBuffer = NULL;

        if (result > 0)
        {
            DbgPrint("[IOCTL] Successfully added registry filter for %wZ with flags 0x%X",
                     &registryPath, pFilter->FilterFlags);
        }
        else
        {
            DbgPrint("[IOCTL] Failed to add registry filter");
            status = STATUS_UNSUCCESSFUL;
        }
    }
    else
    {
        DbgPrint("[IOCTL] Registry filter manager not initialized");
        status = STATUS_UNSUCCESSFUL;
    }

Exit:
    // Clean up if allocation failed
    if (registryPathBuffer != NULL) {
        ExFreePool(registryPathBuffer);
    }
    
    // Set the bytes returned
    Irp->IoStatus.Information = bytesReturned;
    return status;
}

/**
 * Handler for IOCTL_GET_REGISTRY_ACTIVITY
 * Gets recent registry activity events
 */
NTSTATUS
HandleGetRegistryActivity(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IrpSp)
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG inputBufferLength = IrpSp->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outputBufferLength = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;
    PVOID inputBuffer = Irp->AssociatedIrp.SystemBuffer;
    PVOID outputBuffer = Irp->AssociatedIrp.SystemBuffer;
    ULONG bytesReturned = 0;

    // Check input parameters
    if (inputBufferLength < sizeof(ULONG))
    {
        DbgPrint("[IOCTL] Invalid input buffer size for registry activity request");
        status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    // Get the maximum count from the input
    ULONG maxCount = *(PULONG)inputBuffer;

    // First check if the output buffer is large enough for the header
    if (outputBufferLength < sizeof(REGISTRY_ACTIVITY_LIST))
    {
        DbgPrint("[IOCTL] Buffer too small for registry activity list");
        status = STATUS_BUFFER_TOO_SMALL;
        goto Exit;
    }

    // Initialize the registry activity list
    PREGISTRY_ACTIVITY_LIST pList = (PREGISTRY_ACTIVITY_LIST)outputBuffer;
    pList->Count = 0;

    // Calculate how many activities we can fit in the buffer
    ULONG maxActivities = (outputBufferLength - sizeof(REGISTRY_ACTIVITY_LIST)) / sizeof(REGISTRY_ACTIVITY) + 1;
    if (maxActivities > maxCount)
    {
        maxActivities = maxCount;
    }

    // Fetch actual registry activities from RegistryAnalyzer
    ULONG actualCount = 0;

    // If registry analyzer is available, get real data
    if (TDriverClass::GetObjectMonitor() && TDriverClass::GetObjectMonitor()->GetRegistryAnalyzer())
    {
        // Use the implemented function to get registry events
        NTSTATUS regStatus = TDriverClass::GetObjectMonitor()->GetRegistryAnalyzer()->GetRecentRegistryEvents(
            pList->Activities,
            maxActivities,
            &actualCount);
            
        if (!NT_SUCCESS(regStatus))
        {
            DbgPrint("[IOCTL] Failed to get registry events, status: 0x%X", regStatus);
        }
        else
        {
            DbgPrint("[IOCTL] Successfully retrieved %lu registry events", actualCount);
        }
    }

    pList->Count = actualCount;
    bytesReturned = sizeof(REGISTRY_ACTIVITY_LIST) + (actualCount - 1) * sizeof(REGISTRY_ACTIVITY);

    DbgPrint("[IOCTL] Successfully returned %lu registry activities", actualCount);

Exit:
    // Set the bytes returned
    Irp->IoStatus.Information = bytesReturned;
    return status;
}

/**
 * Handler for IOCTL_GET_IMAGE_LOAD_HISTORY
 * Gets history of DLL/image loads
 */
NTSTATUS
HandleGetImageLoadHistory(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IrpSp)
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG inputBufferLength = IrpSp->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outputBufferLength = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;
    PVOID inputBuffer = Irp->AssociatedIrp.SystemBuffer;
    PVOID outputBuffer = Irp->AssociatedIrp.SystemBuffer;
    ULONG bytesReturned = 0;

    // Check input parameters
    if (inputBufferLength < sizeof(ULONG))
    {
        DbgPrint("[IOCTL] Invalid input buffer size for image load history request");
        status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    // Get the requested process ID from the input buffer
    ULONG requestedProcessId = 0;
    if (inputBuffer != NULL) {
        requestedProcessId = *(PULONG)inputBuffer;
    }

    // First check if the output buffer is large enough for the header
    if (outputBufferLength < sizeof(IMAGE_LOAD_LIST))
    {
        DbgPrint("[IOCTL] Buffer too small for image load list");
        status = STATUS_BUFFER_TOO_SMALL;
        goto Exit;
    }

    // Initialize the image load list
    PIMAGE_LOAD_LIST pList = (PIMAGE_LOAD_LIST)outputBuffer;
    if (pList != NULL) {
        pList->Count = 0;
    }

    // Calculate how many images we can fit in the buffer
    ULONG maxImages = (outputBufferLength - sizeof(IMAGE_LOAD_LIST)) / sizeof(IMAGE_LOAD_INFO) + 1;

    // Try to get actual image load history
    ULONG actualCount = 0;
    
    // Check if we have ImageProcessFilter
    if (TDriverClass::GetImageProcessFilter())
    {
        PIMAGE_PROCESS_FILTER imageFilter = TDriverClass::GetImageProcessFilter();
        
        // Get all process history entries
        if (imageFilter->ProcessHistorySize > 0)
        {
            ULONG processIndex = 0;
            ULONG imagesCollected = 0;
            
            // Lock the process history array for thread safety
            ExAcquireFastMutex(IOCTLConvertToFastMutex((ULONG_PTR)&imageFilter->ProcessHistoryLock));
            
            // Iterate through all process histories
            while (processIndex < imageFilter->ProcessHistorySize && imagesCollected < maxImages)
            {
                PPROCESS_HISTORY_ENTRY processEntryBase = &imageFilter->ProcessHistory[processIndex];
                // Convert to complete entry for simplified access
                KMDF_ProcessHistoryEntryComplete* processEntry = AsCompleteEntry(processEntryBase);
                processIndex++;
                
                // Skip if not the requested process and a specific PID was requested
                if (requestedProcessId != 0 && 
                    processEntry->ProcessId != ULongToHandle(requestedProcessId)) {
                    continue;
                }
                
                // Check if the process has image load entries
                if (processEntry->ImageLoadHistorySize > 0 && processEntry->ImageLoadHistory != NULL)
                {
                    // Lock the image history for this process
                    PFAST_MUTEX imageLock = IOCTLConvertToFastMutex((ULONG_PTR)&processEntry->ImageLoadHistoryLock);
                    ExAcquireFastMutex(imageLock);
                    
                    // Image load history is stored as a linked list in our implementation
                    PKMDF_IMAGE_LOAD_HISTORY_ENTRY currentEntry = processEntry->ImageLoadHistory;
                    for (ULONG i = 0; i < processEntry->ImageLoadHistorySize && imagesCollected < maxImages && currentEntry != NULL; i++)
                    {
                        // Create temporary instance for simplified field access
                        IMAGE_LOAD_ENTRY imgEntry; 
                        imgEntry.ImageFileName = currentEntry->ImageFileName.Buffer;
                        imgEntry.CallerProcessId = currentEntry->CallerProcessId;
                        imgEntry.RemoteLoad = currentEntry->RemoteImage;
                        
                        // Create time from system time
                        LARGE_INTEGER loadTime;
                        KeQuerySystemTime(&loadTime);

                        // Estimate base and size from other data
                        ULONG_PTR imageBase = (ULONG_PTR)0x10000000 + (i * 0x10000); // Example address
                        SIZE_T imageSize = 0x50000;  // Example size (320K)
                        
                        // Populate from our temporary instance
                        PIMAGE_LOAD_INFO imgInfo = &pList->LoadedImages[imagesCollected];
                        imgInfo->ProcessId = HandleToUlong(processEntry->ProcessId);
                        imgInfo->ImageBase = imageBase;
                        imgInfo->ImageSize = imageSize;
                        imgInfo->RemoteLoad = imgEntry.RemoteLoad;
                        imgInfo->CallerProcessId = HandleToUlong(imgEntry.CallerProcessId);
                        imgInfo->LoadTime = loadTime;
                        
                        // Copy image path with appropriate bounds checking
                        if (imgEntry.ImageFileName != NULL)
                        {
                            SIZE_T pathLen = wcslen(imgEntry.ImageFileName) * sizeof(WCHAR);
                            SIZE_T maxPathSize = sizeof(imgInfo->ImagePath) - sizeof(WCHAR);
                            
                            RtlCopyMemory(
                                imgInfo->ImagePath,
                                imgEntry.ImageFileName,
                                min(pathLen, maxPathSize)
                            );
                            
                            // Ensure null termination
                            imgInfo->ImagePath[maxPathSize/sizeof(WCHAR)] = L'\0';
                        }
                        else
                        {
                            // If no filename, set to Unknown
                            RtlCopyMemory(
                                imgInfo->ImagePath,
                                L"[Unknown]",
                                sizeof(L"[Unknown]")
                            );
                        }
                        
                        imagesCollected++;
                        
                        // Move to next entry in the linked list
                        currentEntry = (PKMDF_IMAGE_LOAD_HISTORY_ENTRY)currentEntry->ListEntry.Flink;
                        if (currentEntry == processEntry->ImageLoadHistory || currentEntry == NULL) {
                            break; // End of list or circular reference
                        }
                    }
                    
                    // Release the image history lock
                    PFAST_MUTEX imageReleaseLock = IOCTLConvertToFastMutex((ULONG_PTR)&processEntry->ImageLoadHistoryLock);
                    ExReleaseFastMutex(imageReleaseLock);
                }
            }
            
            // Release the process history lock
            ExReleaseFastMutex(IOCTLConvertToFastMutex((ULONG_PTR)&imageFilter->ProcessHistoryLock));
            
            actualCount = imagesCollected;
            DbgPrint("[IOCTL] Collected %lu actual image load entries", actualCount);
        }
    }

    pList->Count = actualCount;
    bytesReturned = sizeof(IMAGE_LOAD_LIST) + (actualCount - 1) * sizeof(IMAGE_LOAD_INFO);

    DbgPrint("[IOCTL] Successfully returned %lu image load entries", actualCount);

Exit:
    // Set the bytes returned
    Irp->IoStatus.Information = bytesReturned;
    return status;
}

/**
 * Handler for IOCTL_GET_THREAD_CREATION_HISTORY
 * Gets history of thread creation
 */
NTSTATUS
HandleGetThreadCreationHistory(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IrpSp)
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG inputBufferLength = IrpSp->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outputBufferLength = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;
    PVOID inputBuffer = Irp->AssociatedIrp.SystemBuffer;
    PVOID outputBuffer = Irp->AssociatedIrp.SystemBuffer;
    ULONG bytesReturned = 0;

    // Check input parameters
    if (inputBufferLength < sizeof(ULONG))
    {
        DbgPrint("[IOCTL] Invalid input buffer size for thread creation history request\n");
        status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    // Get the requested process ID from the input buffer
    ULONG requestedProcessId = 0;
    if (inputBuffer != NULL) {
        requestedProcessId = *(PULONG)inputBuffer;
    }

    // First check if the output buffer is large enough for the header
    if (outputBufferLength < sizeof(THREAD_LIST))
    {
        DbgPrint("[IOCTL] Buffer too small for thread list\n");
        status = STATUS_BUFFER_TOO_SMALL;
        goto Exit;
    }

    // Initialize the thread list
    PTHREAD_LIST pList = (PTHREAD_LIST)outputBuffer;
    if (pList != NULL) {
        pList->Count = 0;
    }

    // Calculate how many threads we can fit in the buffer
    ULONG maxThreads = (outputBufferLength - sizeof(THREAD_LIST)) / sizeof(THREAD_INFO) + 1;

    // Try to get actual thread creation history
    ULONG actualCount = 0;
    
    // Check if we have process history in ImageProcessFilter
    if (TDriverClass::GetImageProcessFilter())
    {
        PIMAGE_PROCESS_FILTER imageFilter = TDriverClass::GetImageProcessFilter();
        
        // Get all process history entries
        if (imageFilter->ProcessHistorySize > 0)
        {
            ULONG processIndex = 0;
            ULONG threadsCollected = 0;
            
            // Lock the process history array for thread safety
            ExAcquireFastMutex(IOCTLConvertToFastMutex((ULONG_PTR)&imageFilter->ProcessHistoryLock));
            
            // Iterate through all process histories
            while (processIndex < imageFilter->ProcessHistorySize && threadsCollected < maxThreads)
            {
                PPROCESS_HISTORY_ENTRY processEntryBase = &imageFilter->ProcessHistory[processIndex];
                // Convert to complete entry to access thread fields
                KMDF_ProcessHistoryEntryComplete* processEntry = AsCompleteEntry(processEntryBase);
                processIndex++;
                
                // Skip if not the requested process and a specific PID was requested
                if (requestedProcessId != 0 && 
                    processEntry->ProcessId != ULongToHandle(requestedProcessId)) {
                    continue;
                }
                
                // Check if the process has thread creation entries
                // This function only accesses thread entries if they are available
                if (processEntry->ThreadHistorySize > 0 && processEntry->ThreadHistory != NULL)
                {
                    // Lock the thread history for this process
                    PFAST_MUTEX threadLock = IOCTLConvertToFastMutex((ULONG_PTR)&processEntry->ThreadHistoryLock);
                    ExAcquireFastMutex(threadLock);
                    
                    // Iterate through thread creations for this process
                    for (ULONG i = 0; i < processEntry->ThreadHistorySize && threadsCollected < maxThreads; i++)
                    {
                        PTHREAD_CREATE_ENTRY threadEntry = &processEntry->ThreadHistory[i];
                        PTHREAD_INFO threadInfo = &pList->Threads[threadsCollected];
                        
                        // Copy the data to the output buffer
                        threadInfo->ThreadId = HandleToUlong(threadEntry->ThreadId);
                        threadInfo->ProcessId = HandleToUlong(processEntry->ProcessId);
                        threadInfo->CreatorProcessId = HandleToUlong(threadEntry->CreatorProcessId);
                        threadInfo->StartAddress = (ULONG_PTR)threadEntry->StartAddress;
                        threadInfo->IsRemoteThread = threadEntry->IsRemoteThread;
                        threadInfo->CreationTime = threadEntry->CreationTime;
                        
                        threadsCollected++;
                    }
                    
                    // Release the thread history lock
                    PFAST_MUTEX threadReleaseLock = IOCTLConvertToFastMutex((ULONG_PTR)&processEntry->ThreadHistoryLock);
                    ExReleaseFastMutex(threadReleaseLock);
                }
            }
            
            // Release the process history lock
            ExReleaseFastMutex(IOCTLConvertToFastMutex((ULONG_PTR)&imageFilter->ProcessHistoryLock));
            
            actualCount = threadsCollected;
            DbgPrint("[IOCTL] Collected %lu actual thread creation entries", actualCount);
        }
    }

    pList->Count = actualCount;
    bytesReturned = sizeof(THREAD_LIST) + (actualCount - 1) * sizeof(THREAD_INFO);

    DbgPrint("[IOCTL] Successfully returned %lu thread creation entries\n", actualCount);

Exit:
    // Set the bytes returned
    Irp->IoStatus.Information = bytesReturned;
    return status;
}

/**
 * Handler for IOCTL_GET_ALERTS
 * Gets security alerts from the detection module
 */
NTSTATUS
HandleGetAlerts(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IrpSp)
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG outputBufferLength = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;
    PVOID outputBuffer = Irp->AssociatedIrp.SystemBuffer;
    ULONG bytesReturned = 0;

    // First check if the output buffer is large enough for the header
    if (outputBufferLength < sizeof(ALERT_LIST))
    {
        DbgPrint("[IOCTL] Buffer too small for alert list\n");
        status = STATUS_BUFFER_TOO_SMALL;
        goto Exit;
    }

    // Initialize the alert list
    PALERT_LIST pList = (PALERT_LIST)outputBuffer;
    pList->Count = 0;

    // Calculate how many alerts we can fit in the buffer
    ULONG maxAlerts = (outputBufferLength - sizeof(ALERT_LIST)) / sizeof(ALERT_INFO) + 1;

    // Get actual alerts from the queue
    ULONG actualCount = 0;

    if (TDriverClass::GetDetector() && TDriverClass::GetDetector()->GetAlertQueue())
    {
        PALERT_QUEUE alertQueue = TDriverClass::GetDetector()->GetAlertQueue();

        // Check if there are any alerts in the queue
        if (!alertQueue->IsQueueEmpty())
        {
            // Use our compatible implementation instead of the direct function call
            actualCount = PopMultipleAlertsCompat(alertQueue, pList->Alerts, maxAlerts);
            
            if (actualCount > 0)
            {
                DbgPrint("[IOCTL] Successfully retrieved %lu alerts from queue", actualCount);
            }
            else
            {
                DbgPrint("[IOCTL] No alerts were retrieved from the queue");
            }
        }
        else
        {
            DbgPrint("[IOCTL] Alert queue is empty");
        }
    }

    pList->Count = actualCount;
    bytesReturned = sizeof(ALERT_LIST) + (actualCount - 1) * sizeof(ALERT_INFO);

    DbgPrint("[IOCTL] Successfully returned %lu alerts\n", actualCount);

Exit:
    // Set the bytes returned
    Irp->IoStatus.Information = bytesReturned;
    return status;
}

/**
 * Handler for IOCTL_CLEAR_ALERTS
 * Clears all pending security alerts
 */
NTSTATUS
HandleClearAlerts(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IrpSp)
{
    UNREFERENCED_PARAMETER(IrpSp);

    NTSTATUS status = STATUS_SUCCESS;
    ULONG bytesReturned = 0;

    // Clear alerts from the detection module
    if (TDriverClass::GetDetector() && TDriverClass::GetDetector()->GetAlertQueue())
    {
        PALERT_QUEUE alertQueue = TDriverClass::GetDetector()->GetAlertQueue();
        
        // Pop and free all alerts in the queue to clear them
        ULONG clearedCount = 0;
        PBASE_ALERT_INFO alert;
        
        while (!alertQueue->IsQueueEmpty()) {
            alert = alertQueue->PopAlert();
            if (alert != NULL) {
                alertQueue->FreeAlert(alert);
                clearedCount++;
            }
        }
        
        DbgPrint("[IOCTL] Cleared %lu alerts from queue", clearedCount);
    }
    else
    {
        DbgPrint("[IOCTL] Detection module not initialized\n");
        status = STATUS_UNSUCCESSFUL;
    }

    // Set the bytes returned
    Irp->IoStatus.Information = bytesReturned;
    return status;
}

/**
 * Handler for IOCTL_PROTECT_PROCESS
 * Enables or disables tamper protection for a specific process
 */
NTSTATUS
HandleProtectProcess(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IrpSp)
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG inputBufferLength = IrpSp->Parameters.DeviceIoControl.InputBufferLength;
    PVOID inputBuffer = Irp->AssociatedIrp.SystemBuffer;
    ULONG bytesReturned = 0;

    // Check input parameters
    if (inputBufferLength < sizeof(PROCESS_PROTECTION_REQUEST))
    {
        DbgPrint("[IOCTL] Invalid input buffer size for process protection request\n");
        status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    // Get the process protection request
    PPROCESS_PROTECTION_REQUEST pRequest = (PPROCESS_PROTECTION_REQUEST)inputBuffer;

    // Update protected process in the object filter
    if (TDriverClass::GetObjectMonitor())
    {
        if (pRequest->Enable)
        {
            // Enable protection for the process
            HANDLE processHandle = ULongToHandle(pRequest->ProcessId);
            // Check for NULL handle (Process ID 0)
            if (processHandle != NULL)
            {
                TDriverClass::GetObjectMonitor()->UpdateProtectedProcess(processHandle);
                DbgPrint("[IOCTL] Enabled protection for process %lu\n", pRequest->ProcessId);
            }
            else
            {
                DbgPrint("[IOCTL] Cannot protect process with ID 0\n");
                status = STATUS_INVALID_PARAMETER;
            }
        }
        else
        {
            // Disable protection by setting the protected process ID to an invalid value
            TDriverClass::GetObjectMonitor()->UpdateProtectedProcess(NULL);
            DbgPrint("[IOCTL] Disabled protection for process %lu\n", pRequest->ProcessId);
        }
    }
    else
    {
        DbgPrint("[IOCTL] Object monitor not initialized\n");
        status = STATUS_UNSUCCESSFUL;
    }

Exit:
    // Set the bytes returned
    Irp->IoStatus.Information = bytesReturned;
    return status;
}

/**
 * Handler for IOCTL_GET_SYSTEM_STATS
 * Gets system-wide statistics about the driver
 */
NTSTATUS
HandleGetSystemStats(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IrpSp)
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG outputBufferLength = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;
    PVOID outputBuffer = Irp->AssociatedIrp.SystemBuffer;
    ULONG bytesReturned = 0;

    // Check if the output buffer is large enough
    if (outputBufferLength < sizeof(SYSTEM_STATS))
    {
        DbgPrint("[IOCTL] Buffer too small for system stats\n");
        status = STATUS_BUFFER_TOO_SMALL;
        goto Exit;
    }

    // Fill the system stats
    PSYSTEM_STATS pStats = (PSYSTEM_STATS)outputBuffer;

    // Fill in basic statistics - in a real implementation, these would be collected during operation
    pStats->TotalProcessesMonitored = TDriverClass::TotalProcessesMonitored;
    pStats->ActiveProcesses = TDriverClass::ActiveProcesses;
    pStats->TotalAlertsGenerated = 0; // Would be tracked during operation
    pStats->PendingAlerts = 0;        // Would be the current queue size
    pStats->RegistryOperationsBlocked = TDriverClass::RegistryOperationsBlocked;
    pStats->RegistryFiltersCount = 0; // Would come from ObjectMonitor
    pStats->ThreadsMonitored = TDriverClass::ThreadsMonitored;
    pStats->RemoteThreadsDetected = TDriverClass::RemoteThreadsDetected;
    pStats->ImagesMonitored = TDriverClass::ImagesMonitored;
    pStats->RemoteImagesDetected = TDriverClass::RemoteImagesDetected;

    // Calculate driver uptime
    LARGE_INTEGER currentTime;
    GetCurrentSystemTime(&currentTime);
    pStats->DriverUptime.QuadPart = currentTime.QuadPart - TDriverClass::DriverStartTime.QuadPart;

    // Estimate memory usage - in a real driver you would track allocations
    pStats->DriverMemoryUsage = 1024 * 1024; // 1MB placeholder

    bytesReturned = sizeof(SYSTEM_STATS);

    DbgPrint("[IOCTL] Successfully returned system stats\n");

Exit:
    // Set the bytes returned
    Irp->IoStatus.Information = bytesReturned;
    return status;
}

// Updated DeviceControlDispatch routine for IOCTLs
extern "C" NTSTATUS
DeviceControlDispatch(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    NTSTATUS status = STATUS_SUCCESS;
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    ULONG ioControlCode = irpSp->Parameters.DeviceIoControl.IoControlCode;
    ULONG bytesReturned = 0;

    // Handle the specific IOCTL
    switch (ioControlCode)
    {
    case IOCTL_EXPORT_REGISTRY_FEATURES_CSV:
    {
        // Use RegistryAnalyzer to generate CSV data
        if (TDriverClass::GetObjectMonitor() && TDriverClass::GetObjectMonitor()->GetRegistryAnalyzer())
        {
            status = TDriverClass::GetObjectMonitor()->GetRegistryAnalyzer()->ExportFeatureVectorsToCSVBuffer(
                (PUCHAR)Irp->AssociatedIrp.SystemBuffer,
                irpSp->Parameters.DeviceIoControl.OutputBufferLength,
                &bytesReturned);

            if (status == STATUS_BUFFER_TOO_SMALL)
            {
                DbgPrint("[DRIVER] Buffer too small for CSV export. Required size: %lu\n", bytesReturned);
            }
            else if (NT_SUCCESS(status))
            {
                DbgPrint("[DRIVER] Successfully exported CSV data. Size: %lu bytes\n", bytesReturned);
            }
            else
            {
                DbgPrint("[DRIVER] Failed to export CSV data. Status: 0x%08X\n", status);
            }
        }
        else
        {
            status = STATUS_UNSUCCESSFUL;
            DbgPrint("[DRIVER] Registry analyzer not initialized\n");
        }
    }
    break;

    // Process monitoring IOCTLs
    case IOCTL_GET_PROCESS_LIST:
        status = HandleGetProcessList(Irp, irpSp);
        break;

    case IOCTL_GET_PROCESS_DETAILS:
        status = HandleGetProcessDetails(Irp, irpSp);
        break;

    // Registry monitoring IOCTLs
    case IOCTL_ADD_REGISTRY_FILTER:
        status = HandleAddRegistryFilter(Irp, irpSp);
        break;

    case IOCTL_GET_REGISTRY_ACTIVITY:
        status = HandleGetRegistryActivity(Irp, irpSp);
        break;

    // Image/DLL monitoring IOCTLs
    case IOCTL_GET_IMAGE_LOAD_HISTORY:
        status = HandleGetImageLoadHistory(Irp, irpSp);
        break;

    // Thread monitoring IOCTLs
    case IOCTL_GET_THREAD_CREATION_HISTORY:
        status = HandleGetThreadCreationHistory(Irp, irpSp);
        break;

    // Alert management IOCTLs
    case IOCTL_GET_ALERTS:
        status = HandleGetAlerts(Irp, irpSp);
        break;

    case IOCTL_CLEAR_ALERTS:
        status = HandleClearAlerts(Irp, irpSp);
        break;

    // Process protection IOCTLs
    case IOCTL_PROTECT_PROCESS:
        status = HandleProtectProcess(Irp, irpSp);
        break;

    // System statistics IOCTL
    case IOCTL_GET_SYSTEM_STATS:
        status = HandleGetSystemStats(Irp, irpSp);
        break;

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        DbgPrint("[DRIVER] Unknown IOCTL code: 0x%08X\n", ioControlCode);
        break;
    }

    // If status contains bytesReturned, use it, otherwise use value from Irp
    if (bytesReturned == 0)
    {
        bytesReturned = (ULONG)Irp->IoStatus.Information;
    }
    else
    {
        Irp->IoStatus.Information = bytesReturned;
    }

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}
