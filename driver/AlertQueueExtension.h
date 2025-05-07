/*
 * This file provides extension functions for the AlertQueue
 */
#pragma once

#include "AlertQueue.h"
#include "IOCTLShared.h"

// Function to convert basic alert to ALERT_INFO structure
ULONG PopMultipleAlertsCompat(
    _In_ PALERT_QUEUE AlertQueue,
    _Out_ PALERT_INFO AlertBuffer,
    _In_ ULONG MaxAlerts);
