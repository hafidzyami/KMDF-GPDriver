/*
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE', which is part of this source code package.
 * 
 * COPYRIGHT 2023
 */
#pragma once

#include "..\common.h"
#include "..\shared.h"
#include "..\ImageFilterExtension.h"

// Complete structures that combine and extend the basic structures
// These are mainly used for type conversions and accessing extended fields

// Thread creation entry structure - duplicated from ImageFilterExtension.h for simplicity
typedef struct _THREAD_CREATE_ENTRY {
    HANDLE ThreadId;
    HANDLE CreatorProcessId;
    PVOID StartAddress;
    BOOLEAN IsRemoteThread;
    LARGE_INTEGER CreationTime;
    // Other fields as needed
} THREAD_CREATE_ENTRY, *PTHREAD_CREATE_ENTRY;

// Process history entry complete structure - duplicated from ImageFilterExtension.h for simplicity
typedef struct _PROCESS_HISTORY_ENTRY_COMPLETE {
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
    WCHAR UserName[64];  // Add this field to match PROCESS_INFO
    LARGE_INTEGER CreationTime;  // Add this field to match PROCESS_INFO
} PROCESS_HISTORY_ENTRY_COMPLETE;

// Image load entry for simplified field access
typedef struct _IMAGE_LOAD_ENTRY {
    PWCHAR ImageFileName;
    HANDLE CallerProcessId;
    BOOLEAN RemoteLoad;
    ULONG_PTR ImageBase;
    SIZE_T ImageSize;
} IMAGE_LOAD_ENTRY;

// Helper function to convert ProcessHistoryEntry to complete form - already defined in ImageFilterExtension.h
// KMDF_ProcessHistoryEntryComplete* AsCompleteEntry(PVOID BaseEntry);
