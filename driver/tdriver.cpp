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
    
    __try {
        DbgPrint("[DRIVER:Initialize] Begin component initialization\n");
        DriverObject = Driver;
        DbgPrint("[DRIVER:Initialize] DriverObject assigned\n");
        
        // Clear all pointers first to ensure clean state
        Detector = NULL;
        ImageProcessFilter = NULL;
        ObjectMonitor = NULL;
        DbgPrint("[DRIVER:Initialize] All pointers cleared\n");
        
        // Initialize detection logic with try/except for safety
        __try {
            DbgPrint("[DRIVER:Initialize] Starting detection logic allocation\n");
            Detector = new (NonPagedPool, DETECTION_LOGIC_TAG) DetectionLogic();
            DbgPrint("[DRIVER:Initialize] Detection logic allocated: 0x%p\n", Detector);
            
            if (Detector == NULL) {
                DbgPrint("[DRIVER:Initialize] Failed to allocate space for detection logic\n");
                status = STATUS_NO_MEMORY;
                goto Cleanup;
            }
            DbgPrint("[DRIVER:Initialize] Detection logic initialized successfully\n");
        }
        __except(EXCEPTION_EXECUTE_HANDLER) {
            DbgPrint("[DRIVER:Initialize] Exception during detection logic initialization: 0x%X\n", GetExceptionCode());
            status = STATUS_DRIVER_INTERNAL_ERROR;
            goto Cleanup;
        }
        
        // Initialize image filter with try/except for safety
        __try {
            DbgPrint("[DRIVER:Initialize] Starting image filter allocation\n");
            ImageProcessFilter = new (NonPagedPool, IMAGE_FILTER_TAG) ImageFilter(Detector, &status);
            DbgPrint("[DRIVER:Initialize] ImageFilter constructor returned status: 0x%X\n", status);
            DbgPrint("[DRIVER:Initialize] Image filter allocated: 0x%p\n", ImageProcessFilter);
            
            if (!NT_SUCCESS(status)) {
                DbgPrint("[DRIVER:Initialize] Failed to initialize image process filter with status 0x%X\n", status);
                goto Cleanup;
            }
            
            if (ImageProcessFilter == NULL) {
                DbgPrint("[DRIVER:Initialize] Failed to allocate space for image process filter\n");
                status = STATUS_NO_MEMORY;
                goto Cleanup;
            }
            DbgPrint("[DRIVER:Initialize] Image filter initialized successfully\n");
        }
        __except(EXCEPTION_EXECUTE_HANDLER) {
            DbgPrint("[DRIVER:Initialize] Exception during image filter initialization: 0x%X\n", GetExceptionCode());
            status = STATUS_DRIVER_INTERNAL_ERROR;
            goto Cleanup;
        }
        
        // Initialize object filter with try/except for safety
        __try {
            DbgPrint("[DRIVER:Initialize] Starting object filter allocation\n");
            ObjectMonitor = new (NonPagedPool, OBJECT_FILTER_TAG) ObjectFilter(Driver, RegistryPath, Detector, &status);
            DbgPrint("[DRIVER:Initialize] ObjectFilter constructor returned status: 0x%X\n", status);
            DbgPrint("[DRIVER:Initialize] Object filter allocated: 0x%p\n", ObjectMonitor);
            
            if (!NT_SUCCESS(status)) {
                DbgPrint("[DRIVER:Initialize] Failed to initialize object filter with status 0x%X\n", status);
                goto Cleanup;
            }
            
            if (ObjectMonitor == NULL) {
                DbgPrint("[DRIVER:Initialize] Failed to allocate space for object filter\n");
                status = STATUS_NO_MEMORY;
                goto Cleanup;
            }
            DbgPrint("[DRIVER:Initialize] Object filter initialized successfully\n");
        }
        __except(EXCEPTION_EXECUTE_HANDLER) {
            DbgPrint("[DRIVER:Initialize] Exception during object filter initialization: 0x%X\n", GetExceptionCode());
            status = STATUS_DRIVER_INTERNAL_ERROR;
            goto Cleanup;
        }
        
        DbgPrint("[DRIVER:Initialize] All components initialized successfully\n");
        return STATUS_SUCCESS;
        
    Cleanup:
        // If initialization fails, clean up any components that were created
        DbgPrint("[DRIVER:Initialize] Initialization failed with status 0x%X, cleaning up\n", status);
        TDriverClass::Cleanup();
        DbgPrint("[DRIVER:Initialize] Cleanup completed\n");
        return status;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[DRIVER:Initialize] Unexpected exception during component initialization: 0x%X\n", GetExceptionCode());
        TDriverClass::Cleanup();
        DbgPrint("[DRIVER:Initialize] Cleanup after exception completed\n");
        return STATUS_DRIVER_INTERNAL_ERROR;
    }
}

/**
 * Cleanup PeaceMaker components
 */
VOID
TDriverClass::Cleanup()
{
    DbgPrint("[DRIVER:Cleanup] Starting PeaceMaker component cleanup\n");
    
    __try {
        // Clean up detection logic
        if (Detector != NULL) {
            DbgPrint("[DRIVER:Cleanup] Cleaning detection logic (0x%p)\n", Detector);
            __try {
                Detector->~DetectionLogic();
                DbgPrint("[DRIVER:Cleanup] Detection logic destructor called\n");
                ExFreePoolWithTag(Detector, DETECTION_LOGIC_TAG);
                DbgPrint("[DRIVER:Cleanup] Detection logic memory freed\n");
            }
            __except(EXCEPTION_EXECUTE_HANDLER) {
                DbgPrint("[DRIVER:Cleanup] Exception during detection logic cleanup: 0x%X\n", GetExceptionCode());
            }
            Detector = NULL;
            DbgPrint("[DRIVER:Cleanup] Detection logic pointer nulled\n");
        }
        else {
            DbgPrint("[DRIVER:Cleanup] Detection logic was NULL, nothing to clean\n");
        }
        
        // Clean up image filter
        if (ImageProcessFilter != NULL) {
            DbgPrint("[DRIVER:Cleanup] Cleaning image filter (0x%p)\n", ImageProcessFilter);
            __try {
                ImageProcessFilter->~ImageFilter();
                DbgPrint("[DRIVER:Cleanup] Image filter destructor called\n");
                ExFreePoolWithTag(ImageProcessFilter, IMAGE_FILTER_TAG);
                DbgPrint("[DRIVER:Cleanup] Image filter memory freed\n");
            }
            __except(EXCEPTION_EXECUTE_HANDLER) {
                DbgPrint("[DRIVER:Cleanup] Exception during image filter cleanup: 0x%X\n", GetExceptionCode());
            }
            ImageProcessFilter = NULL;
            DbgPrint("[DRIVER:Cleanup] Image filter pointer nulled\n");
        }
        else {
            DbgPrint("[DRIVER:Cleanup] Image filter was NULL, nothing to clean\n");
        }
        
        // Clean up object filter
        if (ObjectMonitor != NULL) {
            DbgPrint("[DRIVER:Cleanup] Cleaning object filter (0x%p)\n", ObjectMonitor);
            __try {
                ObjectMonitor->~ObjectFilter();
                DbgPrint("[DRIVER:Cleanup] Object filter destructor called\n");
                ExFreePoolWithTag(ObjectMonitor, OBJECT_FILTER_TAG);
                DbgPrint("[DRIVER:Cleanup] Object filter memory freed\n");
            }
            __except(EXCEPTION_EXECUTE_HANDLER) {
                DbgPrint("[DRIVER:Cleanup] Exception during object filter cleanup: 0x%X\n", GetExceptionCode());
            }
            ObjectMonitor = NULL;
            DbgPrint("[DRIVER:Cleanup] Object filter pointer nulled\n");
        }
        else {
            DbgPrint("[DRIVER:Cleanup] Object filter was NULL, nothing to clean\n");
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[DRIVER:Cleanup] Unexpected exception during component cleanup: 0x%X\n", GetExceptionCode());
    }
    
    DbgPrint("[DRIVER:Cleanup] PeaceMaker components cleanup completed\n");
}

// Untuk memastikan kode C bisa digunakan di C++
extern "C" {

/**
 * CreateClose dispatch routine - handle IRP_MJ_CREATE and IRP_MJ_CLOSE
 */
NTSTATUS
CreateCloseDispatch(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

/**
 * DeviceControl dispatch routine - handle IRP_MJ_DEVICE_CONTROL
 * Deklarasi sebagai extern untuk menghindari konflik dengan implementasi di IOCTLHandlers.cpp
 */
extern NTSTATUS
DeviceControlDispatch(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
);

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT Driver,
    _In_ PUNICODE_STRING RegistryPath
) {
    NTSTATUS status = STATUS_SUCCESS;
    UNICODE_STRING deviceName;
    UNICODE_STRING dosDeviceName;
    PDEVICE_OBJECT deviceObject = NULL;

    DbgPrint("[DRIVER] DriverEntry - Start\n");

    // Initialize TDriverClass static members first to ensure they're not NULL
    TDriverClass::DriverObject = Driver;
    TDriverClass::Detector = NULL;
    TDriverClass::ImageProcessFilter = NULL;
    TDriverClass::ObjectMonitor = NULL;
    DbgPrint("[DRIVER] Static members initialized\n");

    // Initialize driver start time for uptime calculation
    KeQuerySystemTime(&TDriverClass::DriverStartTime);
    DbgPrint("[DRIVER] Driver start time initialized\n");
    
    // Initialize statistics counters
    TDriverClass::TotalProcessesMonitored = 0;
    TDriverClass::ActiveProcesses = 0;
    TDriverClass::RegistryOperationsBlocked = 0;
    TDriverClass::ThreadsMonitored = 0;
    TDriverClass::RemoteThreadsDetected = 0;
    TDriverClass::ImagesMonitored = 0;
    TDriverClass::RemoteImagesDetected = 0;
    DbgPrint("[DRIVER] Statistics counters initialized\n");
    
    DbgPrint("[DRIVER] Driver entry starting");

    // Create device object for IOCTL communication
    RtlInitUnicodeString(&deviceName, L"\\Device\\RegistryAnalyzer");
    RtlInitUnicodeString(&dosDeviceName, L"\\DosDevices\\RegistryAnalyzer");
    DbgPrint("[DRIVER] Device names initialized\n");

    status = IoCreateDevice(
        Driver,
        0,
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &deviceObject
    );
    DbgPrint("[DRIVER] IoCreateDevice called, status: 0x%08X\n", status);

    if (!NT_SUCCESS(status)) {
        DbgPrint("[DRIVER] Failed to create device object, status: 0x%08X\n", status);
        return status;
    }

    // Create symbolic link for user mode access
    status = IoCreateSymbolicLink(&dosDeviceName, &deviceName);
    DbgPrint("[DRIVER] IoCreateSymbolicLink called, status: 0x%08X\n", status);
    
    if (!NT_SUCCESS(status)) {
        DbgPrint("[DRIVER] Failed to create symbolic link, status: 0x%08X\n", status);
        IoDeleteDevice(deviceObject);
        return status;
    }

    // Set dispatch routines
    Driver->MajorFunction[IRP_MJ_CREATE] = CreateCloseDispatch;
    Driver->MajorFunction[IRP_MJ_CLOSE] = CreateCloseDispatch;
    Driver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControlDispatch;
    DbgPrint("[DRIVER] Dispatch routines set\n");

    // Set unload routine
    Driver->DriverUnload = DriverUnload;
    DbgPrint("[DRIVER] Unload routine set\n");

    // Initialize PeaceMaker components
    DbgPrint("[DRIVER] Starting TDriverClass::Initialize\n");
    status = TDriverClass::Initialize(Driver, RegistryPath);
    DbgPrint("[DRIVER] TDriverClass::Initialize returned: 0x%08X\n", status);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[DRIVER] Failed to initialize PeaceMaker components, status: 0x%08X\n", status);
        return status;
    }

    // Register callbacks with proper error handling - simple version for reliability
    DbgPrint("[DRIVER] About to register process notification callback\n");
    status = PsSetCreateProcessNotifyRoutine(ProcessNotifyCallbackRoutine, FALSE);
    DbgPrint("[DRIVER] PsSetCreateProcessNotifyRoutine returned: 0x%08X\n", status);
    
    if (!NT_SUCCESS(status)) {
        DbgPrint("[DRIVER] Failed to register process notification, status: 0x%08X\n", status);
        TDriverClass::Cleanup();
        IoDeleteSymbolicLink(&dosDeviceName);
        IoDeleteDevice(deviceObject);
        return status;
    }
    
    DbgPrint("[DRIVER] Process notification callback registered successfully\n");

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
VOID
ProcessNotifyCallbackRoutine(
    _In_ HANDLE ParentId,
    _In_ HANDLE ProcessId,
    _In_ BOOLEAN Create
)
{
    // Use try/except to prevent crashes
    __try {
        // Handle process creation
        if (Create) {
            DbgPrint("[PROCESS-CREATE] PID: %llu, Parent PID: %llu\n", 
                     (ULONGLONG)ProcessId, (ULONGLONG)ParentId);
            
            // Update statistics safely
            InterlockedIncrement((PLONG)&TDriverClass::TotalProcessesMonitored);
            InterlockedIncrement((PLONG)&TDriverClass::ActiveProcesses);
        }
        // Handle process termination
        else {
            DbgPrint("[PROCESS-TERMINATE] PID: %llu\n", (ULONGLONG)ProcessId);
            
            // Update statistics safely
            if (TDriverClass::ActiveProcesses > 0) {
                InterlockedDecrement((PLONG)&TDriverClass::ActiveProcesses);
            }
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[PROCESS-NOTIFY] Exception in callback: 0x%X\n", GetExceptionCode());
    }
}

void
CleanupProcessMonitoring()
{
    NTSTATUS status;
    
    // Simple unregistration matching our simplified registration
    status = PsSetCreateProcessNotifyRoutine(ProcessNotifyCallbackRoutine, TRUE);
    
    if (NT_SUCCESS(status)) {
        DbgPrint("[PROCESS-MONITOR] Process monitoring cleanup complete\n");
    }
    else {
        DbgPrint("[PROCESS-MONITOR] Process monitoring cleanup failed, status: 0x%08X\n", status);
    }
}

/**
 * Driver unload routine - clean up resources
 */
void
DriverUnload(
    IN PDRIVER_OBJECT DriverObject
)
{
    UNICODE_STRING dosDeviceName;

    // Delete symbolic link
    RtlInitUnicodeString(&dosDeviceName, L"\\DosDevices\\RegistryAnalyzer");
    IoDeleteSymbolicLink(&dosDeviceName);

    // Delete device object
    if (DriverObject->DeviceObject != NULL) {
        IoDeleteDevice(DriverObject->DeviceObject);
    }

    // Cleanup process monitoring
    CleanupProcessMonitoring();
    
    // Cleanup PeaceMaker components
    TDriverClass::Cleanup();

    DbgPrint("[DRIVER] Driver unloaded\n");
}

} // extern "C"
