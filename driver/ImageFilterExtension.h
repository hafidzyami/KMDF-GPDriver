/*
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE', which is part of this source code package.
 * 
 * COPYRIGHT 2023
 */
#pragma once

#include "common.h"
#include "shared.h"
#include "ImageFilter.h"

// Forward declaration of needed types
typedef class ImageFilter PIMAGE_FILTER, *PIMAGE_PROCESS_FILTER;
typedef struct _PROCESS_HISTORY_ENTRY PROCESS_HISTORY_ENTRY, *PPROCESS_HISTORY_ENTRY;

// Extended version of IMAGE_LOAD_HISTORY_ENTRY
typedef struct _KMDF_IMAGE_LOAD_HISTORY_ENTRY {
    LIST_ENTRY ListEntry;
    UNICODE_STRING ImageFileName;
    HANDLE CallerProcessId;
    BOOLEAN RemoteImage;
    // Additional fields as needed
} KMDF_IMAGE_LOAD_HISTORY_ENTRY, *PKMDF_IMAGE_LOAD_HISTORY_ENTRY;

// Extended version of ProcessHistoryEntry with additional fields
typedef struct _KMDF_ProcessHistoryEntryComplete {
    // Base fields from PROCESS_HISTORY_ENTRY
    HANDLE ProcessId;
    UNICODE_STRING ImageFileName;
    UNICODE_STRING CommandLine;
    
    // Extended fields
    ULONG ImageLoadHistorySize;
    PKMDF_IMAGE_LOAD_HISTORY_ENTRY ImageLoadHistory;
    ULONG_PTR ImageLoadHistoryLock;
    ULONG ThreadHistorySize;
    struct _THREAD_CREATE_ENTRY* ThreadHistory;
    ULONG_PTR ThreadHistoryLock;
    BOOLEAN IsTerminated;
    // Other fields that might be needed
} KMDF_ProcessHistoryEntryComplete;

// Thread creation entry structure
typedef struct _THREAD_CREATE_ENTRY {
    HANDLE ThreadId;
    HANDLE CreatorProcessId;
    PVOID StartAddress;
    BOOLEAN IsRemoteThread;
    LARGE_INTEGER CreationTime;
    // Other fields as needed
} THREAD_CREATE_ENTRY, *PTHREAD_CREATE_ENTRY;

// Helper function to convert ProcessHistoryEntry to complete form
inline KMDF_ProcessHistoryEntryComplete* AsCompleteEntry(PVOID BaseEntry) {
    return reinterpret_cast<KMDF_ProcessHistoryEntryComplete*>(BaseEntry);
}
