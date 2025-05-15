#include "pch.h"
#include "tdriver.h"
#include "fixed_structures.h"
#include "AlertQueueExtension.h"

// Define our own conversion function directly in this file to avoid conflicts
inline PFAST_MUTEX IOCTLConvertToFastMutex(ULONG_PTR ptr)
{
    // Validasi range alamat kernel (batas atas)
    if (ptr < 0xFFFF800000000000)
    {
        DbgPrint("[IOCTL] INVALID POINTER CONVERSION: %p is not a valid kernel address", (PVOID)ptr);
        return NULL;
    }

    // Validasi pointer tidak NULL
    if (ptr == 0)
    {
        DbgPrint("[IOCTL] NULL POINTER CONVERSION");
        return NULL;
    }

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
    if (AlertQueue == NULL || AlertBuffer == NULL || MaxAlerts == 0)
    {
        return 0;
    }

    ULONG alertCount = 0;
    PBASE_ALERT_INFO baseAlert;

    // Pop up to MaxAlerts alerts from the queue
    while (!AlertQueue->IsQueueEmpty() && alertCount < MaxAlerts)
    {
        baseAlert = AlertQueue->PopAlert();
        if (baseAlert == NULL)
        {
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
NTSTATUS HandleGetProcessList(_In_ PIRP Irp, _In_ PIO_STACK_LOCATION IrpSp)
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG outputBufferLength = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;
    PVOID outputBuffer = Irp->AssociatedIrp.SystemBuffer;
    ULONG bytesReturned = 0;
    PPROCESS_SUMMARY_ENTRY processSummaries = NULL;

    // Add detailed debug logging
    DbgPrint("[IOCTL] HandleGetProcessList called, outputBufferLength=%lu", outputBufferLength);

    // Get the overall stats to compare
    DbgPrint("[IOCTL] Stats: TotalProcessesMonitored=%lu, ActiveProcesses=%lu",
             TDriverClass::TotalProcessesMonitored,
             TDriverClass::ActiveProcesses);

    // Log ProcessHistorySize if available
    if (TDriverClass::GetImageProcessFilter() != NULL)
    {
        DbgPrint("[IOCTL] ImageProcessFilter->ProcessHistorySize=%llu",
                 TDriverClass::GetImageProcessFilter()->ProcessHistorySize);
    }

    // Calculate max processes correctly
    ULONG maxProcesses = 0;

    // Calculate how many total processes will fit in the output buffer
    if (outputBufferLength >= sizeof(PROCESS_LIST))
    {
        // Calculate how many total processes will fit
        SIZE_T availableSpace = outputBufferLength - sizeof(ULONG);
        maxProcesses = (ULONG)(availableSpace / sizeof(PROCESS_INFO));

        // Always make sure we can at least return one process
        maxProcesses = max(1, maxProcesses);

        DbgPrint("[IOCTL] Output buffer can hold up to %lu processes (sizeof(PROCESS_INFO)=%lu bytes)",
                 maxProcesses, (ULONG)sizeof(PROCESS_INFO));
    }

    // Initialize the count to 0, will be updated as we fill the list
    PPROCESS_LIST pList = (PPROCESS_LIST)outputBuffer;
    if (pList == NULL)
    {
        DbgPrint("[IOCTL] Output buffer is NULL");
        status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    pList->Count = 0;

    // Check if ImageProcessFilter is initialized
    if (TDriverClass::GetImageProcessFilter() == NULL)
    {
        DbgPrint("[IOCTL] ImageProcessFilter is not initialized");
        pList->Count = 0;
        bytesReturned = sizeof(PROCESS_LIST);
        status = STATUS_SUCCESS; // Return empty list instead of failing
        goto Exit;
    }

    // Only proceed if we have actual process data and maxProcesses > 0
    if (maxProcesses > 0)
    {
        // Allocate memory for process summaries
        processSummaries =
            (PPROCESS_SUMMARY_ENTRY)ExAllocatePool2(POOL_FLAG_PAGED, maxProcesses * sizeof(PROCESS_SUMMARY_ENTRY), 'PROS');

        if (processSummaries == NULL)
        {
            DbgPrint("[IOCTL] Failed to allocate memory for process summaries");
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto Exit;
        }

        RtlZeroMemory(processSummaries, maxProcesses * sizeof(PROCESS_SUMMARY_ENTRY));

        DbgPrint("[IOCTL] Calling GetProcessHistorySummary with maxProcesses=%lu", maxProcesses);

        // Get the process summaries with proper error handling
        ULONG actualCount = 0;
        __try
        {
            PIMAGE_PROCESS_FILTER filter = TDriverClass::GetImageProcessFilter();
            actualCount = filter->GetProcessHistorySummary(
                0,                // Skip count - start from the beginning
                processSummaries, // Buffer for summaries
                maxProcesses      // Maximum processes to return
            );

            DbgPrint("[IOCTL] GetProcessHistorySummary returned %lu entries", actualCount);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            DbgPrint("[IOCTL] Exception occurred while getting process history summaries: 0x%X",
                     GetExceptionCode());
            actualCount = 0; // Reset count on exception
        }

        // Convert PROCESS_SUMMARY_ENTRY to PROCESS_INFO
        DbgPrint("[IOCTL] Converting %lu summaries to PROCESS_INFO format", actualCount);

        // Get the process filter for direct access to process history
        PIMAGE_PROCESS_FILTER filter = TDriverClass::GetImageProcessFilter();

        for (ULONG i = 0; i < actualCount && i < maxProcesses; i++)
        {
            // Copy basic process information
            pList->Processes[i].ProcessId = HandleToUlong(processSummaries[i].ProcessId);
            pList->Processes[i].IsTerminated = processSummaries[i].ProcessTerminated;

            // Copy image name with proper bounds checking
            RtlZeroMemory(pList->Processes[i].ImagePath, sizeof(pList->Processes[i].ImagePath));

            if (processSummaries[i].ImageFileName[0] != L'\0')
            {
                RtlCopyMemory(pList->Processes[i].ImagePath,
                              processSummaries[i].ImageFileName,
                              min(sizeof(pList->Processes[i].ImagePath) - sizeof(WCHAR),
                                  wcslen(processSummaries[i].ImageFileName) * sizeof(WCHAR)));
            }

            // Find the original process entry to get ParentProcessId
            PPROCESS_HISTORY_ENTRY originalEntry = NULL;
            for (ULONG64 j = 0; j < filter->ProcessHistorySize; j++)
            {
                if (filter->ProcessHistory[j].ProcessId == processSummaries[i].ProcessId)
                {
                    originalEntry = &filter->ProcessHistory[j];
                    break;
                }
            }

            // Set ParentProcessId and CreationTime if we found the original entry
            if (originalEntry != NULL)
            {
                // Set ParentProcessId
                pList->Processes[i].ParentProcessId = HandleToUlong(originalEntry->ParentId);

                // Set CreationTime
                ULONGLONG epochSeconds = originalEntry->EpochExecutionTime;
                LARGE_INTEGER systemTime;

                // Convert EPOCH time to Windows FILETIME format
                // FILETIME starts from 1601-01-01, EPOCH from 1970-01-01
                // The difference is 11644473600 seconds
                systemTime.QuadPart = (epochSeconds + 11644473600ULL) * 10000000ULL;
                pList->Processes[i].CreationTime = systemTime;

                DbgPrint("[IOCTL] Process %lu: PID=%lu, PPID=%lu, Epoch=%llu",
                         i, pList->Processes[i].ProcessId,
                         pList->Processes[i].ParentProcessId,
                         originalEntry->EpochExecutionTime);
            }
            else
            {
                // Default values if not found
                pList->Processes[i].ParentProcessId = 0;
                pList->Processes[i].CreationTime.QuadPart = 0;

                DbgPrint("[IOCTL] Process %lu: PID=%lu, couldn't find original entry",
                         i, pList->Processes[i].ProcessId);
            }

            // Clear UserName field since we're not using it
            /* RtlZeroMemory(pList->Processes[i].UserName, sizeof(pList->Processes[i].UserName));*/
        }

        pList->Count = actualCount;
        bytesReturned = sizeof(PROCESS_LIST) + (actualCount > 0 ? (actualCount - 1) * sizeof(PROCESS_INFO) : 0);
    }

    DbgPrint("[IOCTL] Final result: returned %lu processes, bytesReturned=%lu",
             pList->Count, bytesReturned);

Exit:
    // Clean up allocated memory if needed
    if (processSummaries != NULL)
    {
        ExFreePool(processSummaries);
    }

    // Set the bytes returned
    Irp->IoStatus.Information = bytesReturned;
    DbgPrint("[IOCTL] HandleGetProcessList completed with status 0x%X", status);
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
    DbgPrint("[IOCTL] GetProcessDetails for PID %lu", processId);

    // First check if the output buffer is large enough for basic process info
    if (outputBufferLength < sizeof(PROCESS_INFO))
    {
        DbgPrint("[IOCTL] Buffer too small for process details");
        status = STATUS_BUFFER_TOO_SMALL;
        goto Exit;
    }

    // Get the ImageProcessFilter pointer
    PIMAGE_PROCESS_FILTER filter = TDriverClass::GetImageProcessFilter();
    if (filter == NULL)
    {
        DbgPrint("[IOCTL] ImageProcessFilter is not initialized");
        status = STATUS_UNSUCCESSFUL;
        goto Exit;
    }

    // Get process details from the image filter
    PROCESS_INFO processInfo;
    RtlZeroMemory(&processInfo, sizeof(PROCESS_INFO));
    
    // Call the new method that handles all the locking properly
    BOOLEAN found = filter->GetProcessDetails(ULongToHandle(processId), &processInfo);
    
    if (found)
    {
        DbgPrint("[IOCTL] Successfully found process %lu details", processId);
    }
    else
    {
        DbgPrint("[IOCTL] Process %lu not found in history", processId);
        // Initialize process info with basic information
        processInfo.ProcessId = processId;
        processInfo.IsTerminated = TRUE; // Assume terminated if not found
    }

    // Copy to output buffer
    RtlCopyMemory(outputBuffer, &processInfo, sizeof(PROCESS_INFO));
    bytesReturned = sizeof(PROCESS_INFO);

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
    WCHAR *registryPathBuffer = NULL;

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
        registryPathBuffer = (WCHAR *)ExAllocatePool2(POOL_FLAG_PAGED,
                                                      (registryPath.Length + sizeof(WCHAR)),
                                                      'REGP');
        if (registryPathBuffer == NULL)
        {
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
    if (registryPathBuffer != NULL)
    {
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

    // Get the requested process ID from the input buffer with safety checks
    ULONG requestedProcessId = 0;
    if (inputBuffer != NULL && inputBufferLength >= sizeof(ULONG))
    {
        __try
        {
            requestedProcessId = *(PULONG)inputBuffer;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            DbgPrint("[IOCTL] Exception when accessing input buffer, code: 0x%08X", GetExceptionCode());
            status = STATUS_INVALID_PARAMETER;
            goto Exit;
        }
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
    if (pList != NULL)
    {
        pList->Count = 0;
    }

    // Calculate how many images we can fit in the buffer
    ULONG maxImages = (outputBufferLength - sizeof(IMAGE_LOAD_LIST)) / sizeof(IMAGE_LOAD_INFO) + 1;

    // Get the ImageProcessFilter
    PIMAGE_FILTER filter = TDriverClass::GetImageProcessFilter();
    if (filter == NULL)
    {
        DbgPrint("[IOCTL] ImageProcessFilter is NULL");
        status = STATUS_UNSUCCESSFUL;
        goto Exit;
    }

    // Get image load history using the safe method
    ULONG actualCount = filter->GetImageLoadHistory(
        ULongToHandle(requestedProcessId),
        pList->LoadedImages,
        maxImages);

    pList->Count = actualCount;
    bytesReturned = sizeof(IMAGE_LOAD_LIST) + (actualCount > 0 ? (actualCount - 1) * sizeof(IMAGE_LOAD_INFO) : 0);

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
        DbgPrint("[IOCTL] Invalid input buffer size for thread creation history request");
        status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    // Get the requested process ID from the input buffer
    ULONG requestedProcessId = 0;
    if (inputBuffer != NULL)
    {
        requestedProcessId = *(PULONG)inputBuffer;
    }

    // First check if the output buffer is large enough for the header
    if (outputBufferLength < sizeof(THREAD_LIST))
    {
        DbgPrint("[IOCTL] Buffer too small for thread list");
        status = STATUS_BUFFER_TOO_SMALL;
        goto Exit;
    }

    // Initialize the thread list
    PTHREAD_LIST pList = (PTHREAD_LIST)outputBuffer;
    if (pList != NULL)
    {
        pList->Count = 0;
    }

    // Calculate how many threads we can fit in the buffer
    ULONG maxThreads = (outputBufferLength - sizeof(THREAD_LIST)) / sizeof(THREAD_INFO) + 1;

    // Get the ImageProcessFilter
    PIMAGE_FILTER filter = TDriverClass::GetImageProcessFilter();
    if (filter == NULL)
    {
        DbgPrint("[IOCTL] ImageProcessFilter is NULL");
        status = STATUS_UNSUCCESSFUL;
        goto Exit;
    }

    // Get thread creation history using the safe method
    ULONG actualCount = filter->GetThreadCreationHistory(
        ULongToHandle(requestedProcessId),
        pList->Threads,
        maxThreads);

    pList->Count = actualCount;
    bytesReturned = sizeof(THREAD_LIST) + (actualCount > 0 ? (actualCount - 1) * sizeof(THREAD_INFO) : 0);

    DbgPrint("[IOCTL] Successfully returned %lu thread creation entries", actualCount);

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

        // Get the total number of alerts in the queue
        ULONG totalAlerts = alertQueue->GetAlertCount();
        DbgPrint("[IOCTL] Total alerts in queue: %lu\n", totalAlerts);
        
        // Allocate a temporary buffer to store all alerts
        if (totalAlerts > 0)
        {
            // Create a copy of all alerts - prevent losing alerts when retrieving them
            PBASE_ALERT_INFO* alertCopies = (PBASE_ALERT_INFO*)ExAllocatePool2(POOL_FLAG_PAGED, 
                                                                          totalAlerts * sizeof(PBASE_ALERT_INFO),
                                                                          'ALCP');
            if (alertCopies == NULL)
            {
                DbgPrint("[IOCTL] Failed to allocate memory for alert copies\n");
                status = STATUS_INSUFFICIENT_RESOURCES;
                goto Exit;
            }

            // First, get all alerts from the queue without removing them
            ULONG fetchedCount = alertQueue->CopyAllAlerts(alertCopies, totalAlerts);
            DbgPrint("[IOCTL] Copied %lu alerts from queue\n", fetchedCount);

            // Convert the temporary alerts to the user-mode format
            // Only copy up to maxAlerts or totalAlerts, whichever is smaller
            ULONG copyCount = min(fetchedCount, maxAlerts);
            
            for (ULONG i = 0; i < copyCount; i++)
            {
                if (alertCopies[i] != NULL)
                {
                    // Convert to ALERT_INFO structure
                    pList->Alerts[i].AlertId = i + 1;
                    pList->Alerts[i].Type = (ALERT_TYPE)alertCopies[i]->AlertType;
                    pList->Alerts[i].SourceProcessId = HandleToUlong(alertCopies[i]->SourceId);

                    // Copy source path
                    RtlZeroMemory(pList->Alerts[i].SourcePath, MAX_PATH * sizeof(WCHAR));
                    RtlCopyMemory(pList->Alerts[i].SourcePath,
                                alertCopies[i]->SourcePath,
                                min(MAX_PATH * sizeof(WCHAR), sizeof(alertCopies[i]->SourcePath)));

                    // Copy target path
                    RtlZeroMemory(pList->Alerts[i].TargetPath, MAX_PATH * sizeof(WCHAR));
                    RtlCopyMemory(pList->Alerts[i].TargetPath,
                                alertCopies[i]->TargetPath,
                                min(MAX_PATH * sizeof(WCHAR), sizeof(alertCopies[i]->TargetPath)));

                    // Get current time
                    KeQuerySystemTime(&pList->Alerts[i].Timestamp);
                    
                    // Set additional fields if they exist in the source
                    if (alertCopies[i]->AlertType == AlertTypeRemoteThreadCreation ||
                        alertCopies[i]->AlertType == AlertTypeParentProcessIdSpoofing)
                    {
                        PREMOTE_OPERATION_ALERT remoteOpAlert = (PREMOTE_OPERATION_ALERT)alertCopies[i];
                        pList->Alerts[i].TargetProcessId = HandleToUlong(remoteOpAlert->RemoteTargetId);
                    }
                    else if (alertCopies[i]->AlertType == AlertTypeStackViolation)
                    {
                        PSTACK_VIOLATION_ALERT stackAlert = (PSTACK_VIOLATION_ALERT)alertCopies[i];
                        pList->Alerts[i].ViolatingAddress = (ULONG_PTR)stackAlert->ViolatingAddress;
                    }
                }
            }

            // Free the temporary alert copies but not the actual alerts
            for (ULONG i = 0; i < fetchedCount; i++)
            {
                // The alert queue will take care of freeing the actual alerts
                // We're just freeing the array that holds the pointers
            }
            ExFreePool(alertCopies);
            
            // Set the count in the result
            actualCount = copyCount;
        }
    }

    pList->Count = actualCount;
    bytesReturned = sizeof(ALERT_LIST) + (actualCount > 0 ? (actualCount - 1) * sizeof(ALERT_INFO) : 0);

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

        while (!alertQueue->IsQueueEmpty())
        {
            alert = alertQueue->PopAlert();
            if (alert != NULL)
            {
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
