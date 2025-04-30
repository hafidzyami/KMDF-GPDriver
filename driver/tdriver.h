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

// Define IOCTL codes for registry feature export
#define IOCTL_REGISTRY_ANALYZER_BASE      0x8000
#define IOCTL_EXPORT_REGISTRY_FEATURES_CSV CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_REGISTRY_ANALYZER_BASE + 1, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Define tags for memory allocation
#define TDRIVER_TAG 'TDrv'
#define DETECTION_LOGIC_TAG 'lDmP'
#define IMAGE_FILTER_TAG 'fImP'
#define OBJECT_FILTER_TAG 'fOmP'

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

#ifdef __cplusplus
}
#endif
