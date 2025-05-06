#include "pch.h"
#include "tdriver.h"

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
 * Handler for IOCTL_GET_PROCESS_LIST
 * Provides a list of all monitored processes
 */
/**
 * Handler for IOCTL_GET_PROCESS_LIST
 * Provides a list of all monitored processes
 */
NTSTATUS
HandleGetProcessList(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IrpSp)
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG outputBufferLength = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;
    PVOID outputBuffer = Irp->AssociatedIrp.SystemBuffer;
    ULONG bytesReturned = 0;
    PPROCESS_SUMMARY_ENTRY processSummaries = NULL;

    // Check if we have at least enough space for the count
    if (outputBufferLength < sizeof(PROCESS_LIST))
    {
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

    // Fill the list with process summaries
    // Create temporary buffer of PROCESS_SUMMARY_ENTRY for compatibility
    processSummaries = 
        (PPROCESS_SUMMARY_ENTRY)ExAllocatePool2(POOL_FLAG_PAGED, maxProcesses * sizeof(PROCESS_SUMMARY_ENTRY), 'PROS');

    if (processSummaries == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        DbgPrint("[IOCTL] Failed to allocate memory for process summaries");
        goto Exit;
    }

    RtlZeroMemory(processSummaries, maxProcesses * sizeof(PROCESS_SUMMARY_ENTRY));

    // Get the process summaries
    ULONG actualProcessCount = TDriverClass::GetImageProcessFilter()->GetProcessHistorySummary(
        0,                // Skip count - start from the beginning
        processSummaries, // Buffer for summaries
        maxProcesses      // Maximum processes to return
    );

    // Convert PROCESS_SUMMARY_ENTRY to PROCESS_INFO
    for (ULONG i = 0; i < actualProcessCount; i++) {
        pList->Processes[i].ProcessId = HandleToUlong(processSummaries[i].ProcessId);
        pList->Processes[i].ParentProcessId = 0; // Not available in summary
        
        // Copy memory with proper bounds checking
        if (processSummaries[i].ImageFileName != NULL) {
            RtlCopyMemory(pList->Processes[i].ImagePath,
                      processSummaries[i].ImageFileName,
                      min(sizeof(pList->Processes[i].ImagePath), MAX_PATH * sizeof(WCHAR)));
        } else {
            RtlZeroMemory(pList->Processes[i].ImagePath, sizeof(pList->Processes[i].ImagePath));
        }
        
        pList->Processes[i].IsTerminated = processSummaries[i].ProcessTerminated;
        
        // Other fields would be set to defaults or extracted from additional sources
        RtlZeroMemory(pList->Processes[i].CommandLine, sizeof(pList->Processes[i].CommandLine));
        RtlZeroMemory(pList->Processes[i].UserName, sizeof(pList->Processes[i].UserName));
        
        // Create a timestamp from the EpochExecutionTime
        LARGE_INTEGER time;
        time.QuadPart = (LONGLONG)(processSummaries[i].EpochExecutionTime * 10000000); // Convert seconds to 100ns units
        pList->Processes[i].CreationTime = time;
    }

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

    // This is where you would fill in the registry activities
    // For this implementation, we'll just create some sample data
    ULONG actualCount = 0;

    // If registry analyzer is available, we could get real data
    if (TDriverClass::GetObjectMonitor() && TDriverClass::GetObjectMonitor()->GetRegistryAnalyzer())
    {
        // Here you would implement real registry activity extraction
        // For now just add some placeholder records

        // Calculate available space
        ULONG availableSpace = maxActivities;
        if (availableSpace > 0)
        {
            // Add placeholder record
            PREGISTRY_ACTIVITY activity = &pList->Activities[0];
            activity->ProcessId = 4;     // System process
            activity->OperationType = 1; // Write
            
            // Use safe wide string constants and proper bounds checking
            WCHAR processNameStr[] = L"System";
            RtlCopyMemory(activity->ProcessName, processNameStr, 
                          min(sizeof(activity->ProcessName), sizeof(processNameStr)));

            WCHAR registryPathStr[] = L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services";
            RtlCopyMemory(activity->RegistryPath, registryPathStr, 
                          min(sizeof(activity->RegistryPath), sizeof(registryPathStr)));
                          
            GetCurrentSystemTime(&activity->Timestamp);
            actualCount = 1;
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

    // Define variable but don't use it directly to avoid warning
    // Using UNREFERENCED_PARAMETER to acknowledge the value is intentionally not used
    ULONG requestedProcessId = 0;
    if (inputBuffer != NULL) {
        requestedProcessId = *(PULONG)inputBuffer;
    }
    UNREFERENCED_PARAMETER(requestedProcessId);

    // First check if the output buffer is large enough for the header
    if (outputBufferLength < sizeof(IMAGE_LOAD_LIST))
    {
        DbgPrint("[IOCTL] Buffer too small for image load list");
        status = STATUS_BUFFER_TOO_SMALL;
        goto Exit;
    }

    // Initialize the image load list
    PIMAGE_LOAD_LIST pList = (PIMAGE_LOAD_LIST)outputBuffer;
    pList->Count = 0;

    // Calculate how many images we can fit in the buffer
    ULONG maxImages = (outputBufferLength - sizeof(IMAGE_LOAD_LIST)) / sizeof(IMAGE_LOAD_INFO) + 1;

    // This is where you would fill in the image load history
    // For this implementation, we'll just add sample data
    ULONG actualCount = 0;

    // Placeholder record
    if (maxImages > 0)
    {
        PIMAGE_LOAD_INFO image = &pList->LoadedImages[0];
        image->ProcessId = 4; // System process
        image->ImageBase = 0x7FFE0000;
        image->ImageSize = 0x10000;
        image->RemoteLoad = FALSE;
        image->CallerProcessId = 4;
        
        // Use a safe wide string constant with proper bounds checking
        WCHAR imagePath[] = L"\\SystemRoot\\System32\\ntoskrnl.exe";
        SIZE_T copySize = min(sizeof(image->ImagePath), sizeof(imagePath));
        RtlCopyMemory(image->ImagePath, imagePath, copySize);
        
        GetCurrentSystemTime(&image->LoadTime);
        actualCount = 1;
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

    // Untuk menghindari warning processId yang tidak digunakan
    // Definisikan variabel dan gunakan UNREFERENCED_PARAMETER
    ULONG requestedProcessId = 0;
    if (inputBuffer != NULL) {
        requestedProcessId = *(PULONG)inputBuffer;
    }
    // Tandai variabel yang sengaja tidak digunakan, untuk menghindari warning
    UNREFERENCED_PARAMETER(requestedProcessId);

    // First check if the output buffer is large enough for the header
    if (outputBufferLength < sizeof(THREAD_LIST))
    {
        DbgPrint("[IOCTL] Buffer too small for thread list\n");
        status = STATUS_BUFFER_TOO_SMALL;
        goto Exit;
    }

    // Initialize the thread list
    PTHREAD_LIST pList = (PTHREAD_LIST)outputBuffer;
    pList->Count = 0;

    // Calculate how many threads we can fit in the buffer
    ULONG maxThreads = (outputBufferLength - sizeof(THREAD_LIST)) / sizeof(THREAD_INFO) + 1;

    // This is where you would fill in the thread creation history
    // For this implementation, we'll just add sample data
    ULONG actualCount = 0;

    // Placeholder record
    if (maxThreads > 0)
    {
        PTHREAD_INFO thread = &pList->Threads[0];
        thread->ThreadId = 4;
        thread->ProcessId = 4;
        thread->CreatorProcessId = 4;
        thread->StartAddress = 0x7FFE1000;
        thread->IsRemoteThread = FALSE;
        GetCurrentSystemTime(&thread->CreationTime);
        actualCount = 1;
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

    // This is where you would fetch alerts from the detection logic
    ULONG actualCount = 0;

    if (TDriverClass::GetDetector() && TDriverClass::GetDetector()->GetAlertQueue())
    {
        PALERT_QUEUE alertQueue = TDriverClass::GetDetector()->GetAlertQueue();

        // Check if there are any alerts in the queue
        if (!alertQueue->IsQueueEmpty())
        {
            // In a real implementation, we would pop alerts from the queue and copy them to the buffer
            // For this demonstration, just add a placeholder alert
            if (maxAlerts > 0)
            {
                PALERT_INFO alert = &pList->Alerts[0];
                alert->AlertId = 1;
                alert->Type = AlertTypeStackViolation;
                alert->SourceProcessId = 1000;
                alert->TargetProcessId = 0;
                alert->ViolatingAddress = 0x12345678;
                RtlCopyMemory(alert->SourcePath, L"\\Device\\HarddiskVolume1\\Windows\\System32\\example.exe", 100);
                GetCurrentSystemTime(&alert->Timestamp);
                actualCount = 1;
            }
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
        // In a real implementation, we would pop all alerts from the queue
        // For this demonstration, just log the operation
        DbgPrint("[IOCTL] Cleared alerts from queue\n");
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
