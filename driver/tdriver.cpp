/*++
// Notice:
//    Use this sample code at your own risk; there is no support from Microsoft for the sample code.
//    In addition, this sample code is licensed to you under the terms of the Microsoft Public License
//    (http://www.microsoft.com/opensource/licenses.mspx)
--*/

#include "pch.h"
#include "tdriver.h"

// Initialize static members of TDriverClass
PDRIVER_OBJECT TDriverClass::DriverObject = NULL;
PDETECTION_LOGIC TDriverClass::Detector = NULL;
PIMAGE_FILTER TDriverClass::ImageProcessFilter = NULL;
POBJECT_FILTER TDriverClass::ObjectMonitor = NULL;

/**
 * Initialize PeaceMaker components
 */
NTSTATUS
TDriverClass::Initialize(
    _In_ PDRIVER_OBJECT Driver,
    _In_ PUNICODE_STRING RegistryPath
)
{
    NTSTATUS status = STATUS_SUCCESS;
    TDriverClass::DriverObject = Driver;
    
    // Initialize detection logic
    TDriverClass::Detector = new (NonPagedPool, DETECTION_LOGIC_TAG) DetectionLogic();
    if (TDriverClass::Detector == NULL) {
        DbgPrint("[DRIVER] Failed to allocate space for detection logic\n");
        return STATUS_NO_MEMORY;
    }
    
    // Initialize image filter
    TDriverClass::ImageProcessFilter = new (NonPagedPool, IMAGE_FILTER_TAG) ImageFilter(TDriverClass::Detector, &status);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[DRIVER] Failed to initialize image process filter with status 0x%X\n", status);
        return status;
    }
    
    if (TDriverClass::ImageProcessFilter == NULL) {
        DbgPrint("[DRIVER] Failed to allocate space for image process filter\n");
        return STATUS_NO_MEMORY;
    }
    
    // Initialize object filter
    TDriverClass::ObjectMonitor = new (NonPagedPool, OBJECT_FILTER_TAG) ObjectFilter(Driver, RegistryPath, TDriverClass::Detector, &status);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[DRIVER] Failed to initialize object filter with status 0x%X\n", status);
        return status;
    }
    
    if (TDriverClass::ObjectMonitor == NULL) {
        DbgPrint("[DRIVER] Failed to allocate space for object filter\n");
        return STATUS_NO_MEMORY;
    }
    
    DbgPrint("[DRIVER] PeaceMaker components initialized successfully\n");
    return STATUS_SUCCESS;
}

/**
 * Cleanup PeaceMaker components
 */
VOID
TDriverClass::Cleanup()
{
    // Clean up detection logic
    if (TDriverClass::Detector != NULL) {
        TDriverClass::Detector->~DetectionLogic();
        ExFreePoolWithTag(TDriverClass::Detector, DETECTION_LOGIC_TAG);
        TDriverClass::Detector = NULL;
    }
    
    // Clean up image filter
    if (TDriverClass::ImageProcessFilter != NULL) {
        TDriverClass::ImageProcessFilter->~ImageFilter();
        ExFreePoolWithTag(TDriverClass::ImageProcessFilter, IMAGE_FILTER_TAG);
        TDriverClass::ImageProcessFilter = NULL;
    }
    
    // Clean up object filter
    if (TDriverClass::ObjectMonitor != NULL) {
        TDriverClass::ObjectMonitor->~ObjectFilter();
        ExFreePoolWithTag(TDriverClass::ObjectMonitor, OBJECT_FILTER_TAG);
        TDriverClass::ObjectMonitor = NULL;
    }
    
    DbgPrint("[DRIVER] PeaceMaker components cleaned up\n");
}

// Untuk memastikan kode C bisa digunakan di C++
extern "C" {

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
) {
    NTSTATUS status = STATUS_SUCCESS;

    // Set unload routine
    DriverObject->DriverUnload = DriverUnload;

    // Initialize PeaceMaker components
    status = TDriverClass::Initialize(DriverObject, RegistryPath);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[DRIVER] Failed to initialize PeaceMaker components, status: 0x%08X\n", status);
        return status;
    }

    // Register callbacks
    status = PsSetCreateProcessNotifyRoutineEx2(
        PsCreateProcessNotifySubsystems,
        (PVOID)ProcessNotifyCallbackRoutine,
        FALSE
    );

    if (!NT_SUCCESS(status)) {
        DbgPrint("[DRIVER] Failed to initialize process monitoring, status: 0x%08X\n", status);
        TDriverClass::Cleanup(); // Clean up PeaceMaker components if registration fails
        return status;
    }

    DbgPrint("[DRIVER] Driver loaded successfully\n");
    return STATUS_SUCCESS;
}

/*
typedef struct _PS_CREATE_NOTIFY_INFO {
    SIZE_T              Size;
    union {
        ULONG Flags;
        struct {
            ULONG FileOpenNameAvailable : 1;
            ULONG IsSubsystemProcess : 1;
            ULONG Reserved : 30;
        };
    };
    HANDLE              ParentProcessId;
    CLIENT_ID           CreatingThreadId;
    struct _FILE_OBJECT* FileObject;
    PCUNICODE_STRING    ImageFileName;
    PCUNICODE_STRING    CommandLine;
    NTSTATUS            CreationStatus;
} PS_CREATE_NOTIFY_INFO, * PPS_CREATE_NOTIFY_INFO;
*/
void
ProcessNotifyCallbackRoutine(
    _In_ PEPROCESS pProcess,
    _In_ HANDLE hPid,
    _In_opt_ PPS_CREATE_NOTIFY_INFO pInfo
)
{
    UNREFERENCED_PARAMETER(pProcess);

    if (pInfo == nullptr) {
        DbgPrint("[PROCESS-TERMINATE] PID: %llu\n", (ULONGLONG)hPid);
        return;
    }

    // Print detailed information about the process being created
    DbgPrint("[PROCESS-CREATE] PID: %llu ----------------------------------------\\\n", (ULONGLONG) hPid);

    DbgPrint("[PROCESS-CREATE] Size of *pInfo structure: %llu\n", pInfo->Size);
    
    DbgPrint("[PROCESS-CREATE] Flags: %lx\n", pInfo->Flags);
    DbgPrint("[PROCESS-CREATE] File Open Name Available: %s\n", pInfo->FileOpenNameAvailable ? "Yes" : "No");
    DbgPrint("[PROCESS-CREATE] Is Subsystem Process: %s\n", pInfo->IsSubsystemProcess ? "Yes" : "No");

    DbgPrint("[PROCESS-CREATE] Parent PID: %llu\n", (ULONGLONG) pInfo->ParentProcessId);
    DbgPrint("[PROCESS-CREATE] Creating Thread ID: %llu (Process: %llu)\n",
        (ULONGLONG) pInfo->CreatingThreadId.UniqueThread, (ULONGLONG) pInfo->CreatingThreadId.UniqueProcess);

    if (pInfo->FileObject != nullptr) DbgPrint("[PROCESS-CREATE] File Object: 0x%p\n", pInfo->FileObject);
    else DbgPrint("[PROCESS-CREATE] File Object: [NULL]\n");

    if (pInfo->ImageFileName != nullptr) DbgPrint("[PROCESS-CREATE] Image: %wZ\n", pInfo->ImageFileName);
    else DbgPrint("[PROCESS-CREATE] Image: [UNKNOWN]\n");

    if (pInfo->CommandLine != nullptr) DbgPrint("[PROCESS-CREATE] Command Line: %wZ\n", pInfo->CommandLine);
    else DbgPrint("[PROCESS-CREATE] Command Line: [NONE]\n");

    DbgPrint("[PROCESS-CREATE] Creation Status: %ld\n", pInfo->CreationStatus);

    DbgPrint("[PROCESS-CREATE]           ----------------------------------------/\n");
}

void
CleanupProcessMonitoring()
{
    PsSetCreateProcessNotifyRoutineEx2(
        PsCreateProcessNotifySubsystems,
        (PVOID)ProcessNotifyCallbackRoutine,
        TRUE
    );
    DbgPrint("[PROCESS-MONITOR] Process monitoring cleanup complete\n");
}

/*
 * Driver unload routine - clean up resources
 */
void
DriverUnload(
    IN PDRIVER_OBJECT DriverObject
)
{
    UNREFERENCED_PARAMETER(DriverObject);

    // Cleanup process monitoring
    CleanupProcessMonitoring();
    
    // Cleanup PeaceMaker components
    TDriverClass::Cleanup();

    DbgPrint("[DRIVER] Driver unloaded\n");
}

} // extern "C"
