/*++
// Notice:
//    Use this sample code at your own risk; there is no support from Microsoft for the sample code.
//    In addition, this sample code is licensed to you under the terms of the Microsoft Public License
//    (http://www.microsoft.com/opensource/licenses.mspx)
--*/

#pragma once

#include "common.h"
#include "DetectionLogic.h"
#include "ImageFilter.h"
#include "ObjectFilter.h"
#include "IOCTLShared.h"  // Include shared IOCTL definitions

// Define tags for memory allocation
#define TDRIVER_TAG 'TDrv'
#define DETECTION_LOGIC_TAG 'lDmP'
#define IMAGE_FILTER_TAG 'fImP'
#define OBJECT_FILTER_TAG 'fOmP'

// Define buffer tags for IOCTLs
#define IOCTL_PROCESS_BUFFER_TAG 'pBmP'    // Process buffer
#define IOCTL_REGISTRY_BUFFER_TAG 'rBmP'   // Registry buffer
#define IOCTL_IMAGE_BUFFER_TAG 'iBmP'      // Image load buffer
#define IOCTL_THREAD_BUFFER_TAG 'tBmP'     // Thread buffer
#define IOCTL_ALERT_BUFFER_TAG 'aBmP'      // Alert buffer

class TDriverClass {
private:
    static PDRIVER_OBJECT DriverObject;
    static PDETECTION_LOGIC Detector;
    static PIMAGE_FILTER ImageProcessFilter;
    static POBJECT_FILTER ObjectMonitor;
public:
    static NTSTATUS Initialize(_In_ PDRIVER_OBJECT Driver, _In_ PUNICODE_STRING RegistryPath);
    static VOID Cleanup();
    static POBJECT_FILTER GetObjectMonitor() {
        return ObjectMonitor;
    }
    static PDETECTION_LOGIC GetDetector() {
        return Detector;
    }
    static PIMAGE_FILTER GetImageProcessFilter() {
        return ImageProcessFilter;
    }
    
    // Added these static variables for statistics
    static LARGE_INTEGER DriverStartTime;
    static ULONG TotalProcessesMonitored;
    static ULONG ActiveProcesses;
    static ULONG RegistryOperationsBlocked;
    static ULONG ThreadsMonitored;
    static ULONG RemoteThreadsDetected;
    static ULONG ImagesMonitored;
    static ULONG RemoteImagesDetected;
};

// Untuk memastikan fungsi-fungsi dapat dipanggil dari kode C++
#ifdef __cplusplus
extern "C" {
#endif

// WDFDRIVER Events
DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;

// IRP Dispatch Routines
NTSTATUS CreateCloseDispatch(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
);

NTSTATUS DeviceControlDispatch(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
);

void CleanupProcessMonitoring();

void
ProcessNotifyCallbackRoutine(
    _In_ PEPROCESS pProcess,
    _In_ HANDLE hPid,
    _In_opt_ PPS_CREATE_NOTIFY_INFO pInfo
);

// IOCTL Handler functions
NTSTATUS
HandleGetProcessList(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IrpSp
);

NTSTATUS
HandleGetProcessDetails(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IrpSp
);

NTSTATUS
HandleAddRegistryFilter(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IrpSp
);

NTSTATUS
HandleGetRegistryActivity(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IrpSp
);

NTSTATUS
HandleGetImageLoadHistory(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IrpSp
);

NTSTATUS
HandleGetThreadCreationHistory(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IrpSp
);

NTSTATUS
HandleGetAlerts(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IrpSp
);

NTSTATUS
HandleClearAlerts(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IrpSp
);

NTSTATUS
HandleProtectProcess(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IrpSp
);

NTSTATUS
HandleGetSystemStats(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IrpSp
);

#ifdef __cplusplus
}
#endif