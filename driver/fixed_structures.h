/*
 * This file provides essential structure definitions needed by IOCTLHandlers.cpp
 */
#pragma once

#include "common.h"
#include "shared.h"
#include "ImageFilter.h"
#include "IOCTLShared.h"

// Define PIMAGE_PROCESS_FILTER as alias to PIMAGE_FILTER for backward compatibility
typedef IMAGE_FILTER *PIMAGE_PROCESS_FILTER;

// Define THREAD_CREATE_ENTRY structure needed by various functions
typedef struct _THREAD_CREATE_ENTRY {
    HANDLE ThreadId;
    HANDLE CreatorProcessId;
    PVOID StartAddress;
    BOOLEAN IsRemoteThread;
    LARGE_INTEGER CreationTime;
} THREAD_CREATE_ENTRY, *PTHREAD_CREATE_ENTRY;

// Define wrapper for complete process history entry
typedef struct _KMDF_ProcessHistoryEntryComplete {
    HANDLE ProcessId;
    UNICODE_STRING ImageFileName;
    UNICODE_STRING CommandLine;
    
    // Extended fields for thread history
    ULONG ThreadHistorySize;
    PTHREAD_CREATE_ENTRY ThreadHistory;
    ULONG_PTR ThreadHistoryLock;
    
    // Extended fields for image history
    ULONG ImageLoadHistorySize;
    struct _KMDF_IMAGE_LOAD_HISTORY_ENTRY* ImageLoadHistory;
    ULONG_PTR ImageLoadHistoryLock;
    
    BOOLEAN IsTerminated;
} KMDF_ProcessHistoryEntryComplete;

// Define IMAGE_LOAD_HISTORY_ENTRY
typedef struct _KMDF_IMAGE_LOAD_HISTORY_ENTRY {
    LIST_ENTRY ListEntry;
    UNICODE_STRING ImageFileName;
    HANDLE CallerProcessId;
    BOOLEAN RemoteImage;
} KMDF_IMAGE_LOAD_HISTORY_ENTRY, *PKMDF_IMAGE_LOAD_HISTORY_ENTRY;

// Define simple image load entry for easier access
typedef struct _IMAGE_LOAD_ENTRY {
    WCHAR* ImageFileName;
    HANDLE CallerProcessId;
    BOOLEAN RemoteLoad;
} IMAGE_LOAD_ENTRY;

// Helper function to convert process entry to complete form
inline KMDF_ProcessHistoryEntryComplete* AsCompleteEntry(PVOID BaseEntry) {
    return reinterpret_cast<KMDF_ProcessHistoryEntryComplete*>(BaseEntry);
}

// Alert compatibility function
ULONG PopMultipleAlertsCompat(
    _In_ PALERT_QUEUE AlertQueue,
    _Out_ PALERT_INFO AlertBuffer,
    _In_ ULONG MaxAlerts);
