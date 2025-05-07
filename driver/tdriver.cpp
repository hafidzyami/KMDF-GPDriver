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
        DbgPrint("[DRIVER] Starting PeaceMaker component initialization\n");
        DriverObject = Driver;
        
        // Clear all pointers first to ensure clean state
        Detector = NULL;
        ImageProcessFilter = NULL;
        ObjectMonitor = NULL;
        
        // Initialize detection logic with try/except for safety
        __try {
            Detector = new (NonPagedPool, DETECTION_LOGIC_TAG) DetectionLogic();
            if (Detector == NULL) {
                DbgPrint("[DRIVER] Failed to allocate space for detection logic\n");
                status = STATUS_NO_MEMORY;
                goto Cleanup;
            }
            DbgPrint("[DRIVER] Detection logic initialized successfully\n");
        }
        __except(EXCEPTION_EXECUTE_HANDLER) {
            DbgPrint("[DRIVER] Exception during detection logic initialization: 0x%X\n", GetExceptionCode());
            status = STATUS_DRIVER_INTERNAL_ERROR;
            goto Cleanup;
        }
        
        // Initialize image filter with try/except for safety
        __try {
            ImageProcessFilter = new (NonPagedPool, IMAGE_FILTER_TAG) ImageFilter(Detector, &status);
            if (!NT_SUCCESS(status)) {
                DbgPrint("[DRIVER] Failed to initialize image process filter with status 0x%X\n", status);
                goto Cleanup;
            }
            
            if (ImageProcessFilter == NULL) {
                DbgPrint("[DRIVER] Failed to allocate space for image process filter\n");
                status = STATUS_NO_MEMORY;
                goto Cleanup;
            }
            DbgPrint("[DRIVER] Image filter initialized successfully\n");
        }
        __except(EXCEPTION_EXECUTE_HANDLER) {
            DbgPrint("[DRIVER] Exception during image filter initialization: 0x%X\n", GetExceptionCode());
            status = STATUS_DRIVER_INTERNAL_ERROR;
            goto Cleanup;
        }
        
        // Initialize object filter with try/except for safety
        __try {
            ObjectMonitor = new (NonPagedPool, OBJECT_FILTER_TAG) ObjectFilter(Driver, RegistryPath, Detector, &status);
            if (!NT_SUCCESS(status)) {
                DbgPrint("[DRIVER] Failed to initialize object filter with status 0x%X\n", status);
                goto Cleanup;
            }
            
            if (ObjectMonitor == NULL) {
                DbgPrint("[DRIVER] Failed to allocate space for object filter\n");
                status = STATUS_NO_MEMORY;
                goto Cleanup;
            }
            DbgPrint("[DRIVER] Object filter initialized successfully\n");
        }
        __except(EXCEPTION_EXECUTE_HANDLER) {
            DbgPrint("[DRIVER] Exception during object filter initialization: 0x%X\n", GetExceptionCode());
            status = STATUS_DRIVER_INTERNAL_ERROR;
            goto Cleanup;
        }
        
        DbgPrint("[DRIVER] PeaceMaker components initialized successfully\n");
        return STATUS_SUCCESS;
        
    Cleanup:
        // If initialization fails, clean up any components that were created
        TDriverClass::Cleanup();
        return status;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[DRIVER] Unexpected exception during component initialization: 0x%X\n", GetExceptionCode());
        TDriverClass::Cleanup();
        return STATUS_DRIVER_INTERNAL_ERROR;
    }
}

/**
 * Cleanup PeaceMaker components
 */
VOID
TDriverClass::Cleanup()
{
    DbgPrint("[DRIVER] Starting PeaceMaker component cleanup\n");
    
    __try {
        // Clean up detection logic
        if (Detector != NULL) {
            __try {
                Detector->~DetectionLogic();
                ExFreePoolWithTag(Detector, DETECTION_LOGIC_TAG);
                DbgPrint("[DRIVER] Detection logic cleaned up\n");
            }
            __except(EXCEPTION_EXECUTE_HANDLER) {
                DbgPrint("[DRIVER] Exception during detection logic cleanup: 0x%X\n", GetExceptionCode());
            }
            Detector = NULL;
        }
        
        // Clean up image filter
        if (ImageProcessFilter != NULL) {
            __try {
                ImageProcessFilter->~ImageFilter();
                ExFreePoolWithTag(ImageProcessFilter, IMAGE_FILTER_TAG);
                DbgPrint("[DRIVER] Image filter cleaned up\n");
            }
            __except(EXCEPTION_EXECUTE_HANDLER) {
                DbgPrint("[DRIVER] Exception during image filter cleanup: 0x%X\n", GetExceptionCode());
            }
            ImageProcessFilter = NULL;
        }
        
        // Clean up object filter
        if (ObjectMonitor != NULL) {
            __try {
                ObjectMonitor->~ObjectFilter();
                ExFreePoolWithTag(ObjectMonitor, OBJECT_FILTER_TAG);
                DbgPrint("[DRIVER] Object filter cleaned up\n");
            }
            __except(EXCEPTION_EXECUTE_HANDLER) {
                DbgPrint("[DRIVER] Exception during object filter cleanup: 0x%X\n", GetExceptionCode());
            }
            ObjectMonitor = NULL;
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[DRIVER] Unexpected exception during component cleanup: 0x%X\n", GetExceptionCode());
    }
    
    DbgPrint("[DRIVER] PeaceMaker components cleanup completed\n");
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

    // Initialize TDriverClass static members first to ensure they're not NULL
    TDriverClass::DriverObject = Driver;
    TDriverClass::Detector = NULL;
    TDriverClass::ImageProcessFilter = NULL;
    TDriverClass::ObjectMonitor = NULL;

    // Initialize driver start time for uptime calculation
    KeQuerySystemTime(&TDriverClass::DriverStartTime);
    
    // Initialize statistics counters
    TDriverClass::TotalProcessesMonitored = 0;
    TDriverClass::ActiveProcesses = 0;
    TDriverClass::RegistryOperationsBlocked = 0;
    TDriverClass::ThreadsMonitored = 0;
    TDriverClass::RemoteThreadsDetected = 0;
    TDriverClass::ImagesMonitored = 0;
    TDriverClass::RemoteImagesDetected = 0;
    
    DbgPrint("[DRIVER] Driver entry starting");

    // Create device object for IOCTL communication
    RtlInitUnicodeString(&deviceName, L"\\Device\\RegistryAnalyzer");
    RtlInitUnicodeString(&dosDeviceName, L"\\DosDevices\\RegistryAnalyzer");

    status = IoCreateDevice(
        Driver,
        0,
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &deviceObject
    );

    if (!NT_SUCCESS(status)) {
        DbgPrint("[DRIVER] Failed to create device object, status: 0x%08X\n", status);
        return status;
    }

    // Create symbolic link for user mode access
    status = IoCreateSymbolicLink(&dosDeviceName, &deviceName);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[DRIVER] Failed to create symbolic link, status: 0x%08X\n", status);
        IoDeleteDevice(deviceObject);
        return status;
    }

    // Set dispatch routines
    Driver->MajorFunction[IRP_MJ_CREATE] = CreateCloseDispatch;
    Driver->MajorFunction[IRP_MJ_CLOSE] = CreateCloseDispatch;
    Driver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControlDispatch;

    // Set unload routine
    Driver->DriverUnload = DriverUnload;

    // Initialize PeaceMaker components
    status = TDriverClass::Initialize(Driver, RegistryPath);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[DRIVER] Failed to initialize PeaceMaker components, status: 0x%08X\n", status);
        return status;
    }

    // Register callbacks with proper error handling - simple version for reliability
    status = PsSetCreateProcessNotifyRoutine(ProcessNotifyCallbackRoutine, FALSE);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[DRIVER] Failed to register process notification, status: 0x%08X\n", status);
        TDriverClass::Cleanup();
        IoDeleteSymbolicLink(&dosDeviceName);
        IoDeleteDevice(deviceObject);
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
