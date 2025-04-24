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
};

// Untuk memastikan fungsi-fungsi dapat dipanggil dari kode C++
#ifdef __cplusplus
extern "C" {
#endif

// WDFDRIVER Events
DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;

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
