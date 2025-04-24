/*++
// Notice:
//    Use this sample code at your own risk; there is no support from Microsoft for the sample code.
//    In addition, this sample code is licensed to you under the terms of the Microsoft Public License
//    (http://www.microsoft.com/opensource/licenses.mspx)
--*/

#pragma once

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
