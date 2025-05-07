/*
 * This file provides the implementation of the PopMultipleAlertsCompat function
 */
#include "pch.h"
#include "AlertQueueExtension.h"

/**
 * Compatibility function to retrieve multiple alerts
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

    // Process as many alerts as we can, up to MaxAlerts
    while (!AlertQueue->IsQueueEmpty() && alertCount < MaxAlerts) {
        // Pop an alert from the queue
        baseAlert = AlertQueue->PopAlert();
        if (baseAlert == NULL) {
            // No more alerts
            break;
        }

        // Convert BASE_ALERT_INFO to ALERT_INFO structure for user mode
        PALERT_INFO currentAlert = &AlertBuffer[alertCount];

        // Fill in the alert info
        currentAlert->AlertId = alertCount + 1; // Assign incremental IDs
        currentAlert->Type = (ALERT_TYPE)baseAlert->AlertType;
        currentAlert->SourceProcessId = HandleToUlong(baseAlert->SourceId);
        currentAlert->TargetProcessId = 0; // Default value
        
        // Set timestamp to current time
        LARGE_INTEGER currentTime;
        KeQuerySystemTime(&currentTime);
        currentAlert->Timestamp = currentTime;
        
        // Default value for violating address
        currentAlert->ViolatingAddress = 0;

        // Handle specific alert types
        if (baseAlert->AlertType == AlertTypeStackViolation) {
            // Handle stack violation alerts
            PSTACK_VIOLATION_ALERT stackAlert = (PSTACK_VIOLATION_ALERT)baseAlert;
            currentAlert->ViolatingAddress = (ULONG_PTR)stackAlert->ViolatingAddress;
        }
        else if (baseAlert->AlertType == AlertTypeRemoteThreadCreation || 
                 baseAlert->AlertType == AlertTypeParentProcessIdSpoofing) {
            // Handle remote operation alerts
            PREMOTE_OPERATION_ALERT remoteAlert = (PREMOTE_OPERATION_ALERT)baseAlert;
            currentAlert->TargetProcessId = HandleToUlong(remoteAlert->RemoteTargetId);
        }

        // Copy strings with proper bounds checking
        if (baseAlert->SourcePath[0] != L'\0') {
            RtlCopyMemory(currentAlert->SourcePath, 
                       baseAlert->SourcePath, 
                       min(sizeof(currentAlert->SourcePath), sizeof(baseAlert->SourcePath)));
        }

        if (baseAlert->TargetPath[0] != L'\0') {
            RtlCopyMemory(currentAlert->TargetPath, 
                       baseAlert->TargetPath, 
                       min(sizeof(currentAlert->TargetPath), sizeof(baseAlert->TargetPath)));
        }

        // Free the base alert as we've copied it to the output buffer
        AlertQueue->FreeAlert(baseAlert);

        // Increment our count
        alertCount++;
    }

    return alertCount;
}
