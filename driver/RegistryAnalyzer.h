/*
 * Registry data analyzer for malware detection
 * Based on K-Means clustering research for registry behavior analysis
 */
#pragma once
#include "common.h"
#include "ObjectFilter.h"
#include "ImageFilter.h"

// Registry analyzer tags
#define REGISTRY_EVENT_TAG 'rEmP'
#define REGISTRY_PROFILE_TAG 'rPmP'
#define REGISTRY_FEATURE_TAG 'rFmP'

// Define registry operation types for better classification
typedef enum _REGISTRY_OPERATION_TYPE {
    RegistryOperationUnknown = 0,
    RegistryOperationCreate = 1,
    RegistryOperationModify = 2,
    RegistryOperationDelete = 3,
    RegistryOperationQuery = 4
} REGISTRY_OPERATION_TYPE;

// Key categories for classification
typedef enum _REGISTRY_KEY_CATEGORY {
    RegistryKeyCategoryNormal = 0,
    RegistryKeyCategoryAutorun = 1,     // Keys related to autorun (startup)
    RegistryKeyCategorySecurity = 2,    // Keys related to security settings
    RegistryKeyCategoryFileAssoc = 3,   // File association keys
    RegistryKeyCategoryNetworking = 4,  // Networking related keys
    RegistryKeyCategoryServices = 5,    // Service related keys
    RegistryKeyCategorySensitive = 6    // Other sensitive keys
} REGISTRY_KEY_CATEGORY;

// Comprehensive registry event data structure
typedef struct _REGISTRY_EVENT_DATA {
    // Basic identification
    HANDLE ProcessId;                    // Process ID performing the operation
    HANDLE ThreadId;                     // Thread ID performing the operation
    PUNICODE_STRING ProcessName;         // Process name
    LARGE_INTEGER Timestamp;             // When the operation occurred
    
    // Registry operation details
    REG_NOTIFY_CLASS NotifyClass;        // Original notification class
    REGISTRY_OPERATION_TYPE OperationType; // Categorized operation type
    PUNICODE_STRING KeyPath;             // Full registry key path
    PUNICODE_STRING ValueName;           // Registry value name if applicable
    ULONG ValueType;                     // Registry value type (REG_SZ, REG_DWORD, etc.)
    ULONG ValueSize;                     // Size of the value data
    PVOID DataBuffer;                    // The actual data (only if size is reasonable)
    ULONG DataBufferSize;                // Size of the allocated buffer
    
    // Contextual information
    BOOLEAN IsRemoteOperation;           // Whether operation comes from another process
    HANDLE ParentProcessId;              // Parent process ID
    REGISTRY_KEY_CATEGORY KeyCategory;   // Category of the accessed key
    
    // List entry for linked list implementation
    LIST_ENTRY ListEntry;
} REGISTRY_EVENT_DATA, *PREGISTRY_EVENT_DATA;

// Process profile structure that aggregates registry operations by process
typedef struct _PROCESS_REGISTRY_PROFILE {
    // Process identification
    HANDLE ProcessId;
    PUNICODE_STRING ProcessName;
    PUNICODE_STRING ProcessPath;
    HANDLE ParentProcessId;
    LARGE_INTEGER FirstSeen;             // First operation timestamp
    LARGE_INTEGER LastSeen;              // Most recent operation timestamp
    
    // Registry operation statistics
    ULONG TotalOperationCount;           // Total registry operations
    ULONG CreateOperationCount;          // Number of create operations
    ULONG ModifyOperationCount;          // Number of modify operations
    ULONG DeleteOperationCount;          // Number of delete operations
    ULONG QueryOperationCount;           // Number of query operations
    
    // Key access patterns
    ULONG UniqueKeysAccessed;            // Number of unique keys accessed
    ULONG AutorunKeysAccessed;           // Number of autorun keys accessed
    ULONG SecurityKeysAccessed;          // Number of security keys accessed
    ULONG FileAssocKeysAccessed;         // Number of file association keys accessed
    ULONG NetworkingKeysAccessed;        // Number of networking keys accessed
    ULONG ServicesKeysAccessed;          // Number of service keys accessed
    ULONG SensitiveKeysAccessed;         // Number of sensitive keys accessed
    
    // Temporal patterns
    ULONG OperationBurstCount;           // Number of operation bursts
    ULONG MaxOperationsPerBurst;         // Maximum operations in a single burst
    ULONG BurstIntervalMs;               // Typical time interval between bursts
    
    // Remote operations
    ULONG RemoteOperationCount;          // Operations performed by other processes
    
    // Suspicious indicators
    ULONG FileExtensionModificationCount; // Count of file extension modifications (ransomware indicator)
    ULONG SecuritySettingModificationCount; // Count of security setting changes
    
    // Raw event storage
    LIST_ENTRY EventList;                // List of registry events
    ULONG EventCount;                    // Number of events stored
    EX_PUSH_LOCK EventLock;              // Lock for event list access
    
    // List management
    LIST_ENTRY ListEntry;                // For linking profiles together
} PROCESS_REGISTRY_PROFILE, *PPROCESS_REGISTRY_PROFILE;

// Feature vector structure to export for clustering in user-mode
typedef struct _REGISTRY_FEATURE_VECTOR {
    // Identification
    HANDLE ProcessId;
    WCHAR ProcessName[MAX_PATH];
    
    // Time metrics
    ULONGLONG FirstSeenTime;             // First operation timestamp (epoch time)
    ULONGLONG LastSeenTime;              // Last operation timestamp (epoch time)
    ULONGLONG OperationDurationSec;      // Total duration of operations
    
    // Operation counts (normalized in user-mode)
    ULONG TotalOperationCount;
    ULONG CreateOperationCount;
    ULONG ModifyOperationCount;
    ULONG DeleteOperationCount;
    ULONG QueryOperationCount;
    
    // Key access patterns
    ULONG UniqueKeysAccessed;
    ULONG AutorunKeysAccessed;
    ULONG SecurityKeysAccessed;
    ULONG FileAssocKeysAccessed;
    ULONG NetworkingKeysAccessed;
    ULONG ServicesKeysAccessed;
    ULONG SensitiveKeysAccessed;
    
    // Burst metrics
    ULONG OperationBurstCount;
    ULONG MaxOperationsPerBurst;
    ULONG BurstIntervalMs;
    
    // Remote operations
    ULONG RemoteOperationCount;
    
    // Suspicious indicators
    ULONG FileExtensionModificationCount;
    ULONG SecuritySettingModificationCount;
    
    // Reserved for future use
    ULONG Reserved[10];
} REGISTRY_FEATURE_VECTOR, *PREGISTRY_FEATURE_VECTOR;

typedef class RegistryAnalyzer
{
private:
    // Global profile list
    LIST_ENTRY ProcessProfileListHead;
    EX_PUSH_LOCK ProcessProfileLock;
    ULONG ProfileCount;
    
    // Known key categories - populated at initialization
    RTL_AVL_TABLE KeyCategoryTable;
    
    // Private methods
    REGISTRY_KEY_CATEGORY CategorizeRegistryKey(
        _In_ PUNICODE_STRING KeyPath
        );
    
    REGISTRY_OPERATION_TYPE MapNotifyClassToOperationType(
        _In_ REG_NOTIFY_CLASS NotifyClass
        );
    
    PPROCESS_REGISTRY_PROFILE FindOrCreateProcessProfile(
        _In_ HANDLE ProcessId
        );
    
    VOID CleanupOldEvents(
        _Inout_ PPROCESS_REGISTRY_PROFILE Profile,
        _In_ ULONG MaxEventsToKeep
        );
    
    BOOLEAN CheckBurstPattern(
        _Inout_ PPROCESS_REGISTRY_PROFILE Profile,
        _In_ LARGE_INTEGER CurrentTime
        );
    
    VOID UpdateKeyAccessStats(
        _Inout_ PPROCESS_REGISTRY_PROFILE Profile,
        _In_ REGISTRY_KEY_CATEGORY KeyCategory
        );
    
    VOID FreeRegistryEvent(
        _In_ PREGISTRY_EVENT_DATA Event
        );
    
    VOID FreeProcessProfile(
        _In_ PPROCESS_REGISTRY_PROFILE Profile
        );

public:
    RegistryAnalyzer();
    ~RegistryAnalyzer();
    
    // Main recording function - called from registry callback
    NTSTATUS RecordRegistryEvent(
        _In_ HANDLE ProcessId,
        _In_ REG_NOTIFY_CLASS NotifyClass,
        _In_ PVOID RegistryObject,
        _In_ PUNICODE_STRING ValueName,
        _In_ PVOID DataBuffer,
        _In_ ULONG DataSize,
        _In_ ULONG ValueType
        );
    
    // Profile management
    ULONG GetProcessProfileCount();
    
    // Extract feature vectors for export to user-mode
    NTSTATUS ExportFeatureVectors(
        _Out_ PREGISTRY_FEATURE_VECTOR FeatureVectors,
        _In_ ULONG MaxFeatureVectors,
        _Out_ PULONG ActualFeatureVectors
        );
    
    // Export feature vectors to a CSV buffer in format ready for saving
    NTSTATUS ExportFeatureVectorsToCSVBuffer(
        _Out_ PUCHAR CSVBuffer,
        _In_ ULONG BufferSize,
        _Out_ PULONG ActualSize
        );
    
    // Cleanup old profiles
    VOID CleanupOldProfiles(
        _In_ LARGE_INTEGER CutoffTime
        );
    
    // Reset all data
    VOID Reset();
    
} REGISTRY_ANALYZER, *PREGISTRY_ANALYZER;
