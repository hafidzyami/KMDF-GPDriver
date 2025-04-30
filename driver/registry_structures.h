/*
 * Complete structure definitions for Registry Analyzer
 */
#pragma once

#include "common_fix.h"

// Registry analyzer tags
#define REGISTRY_EVENT_TAG 'rEmP'
#define REGISTRY_PROFILE_TAG 'rPmP'
#define REGISTRY_FEATURE_TAG 'rFmP'

// Maximum number of feature vectors to export
// No longer used - export all vectors now

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
    RegistryKeyCategorySensitive = 6,   // Other sensitive keys
    RegistryKeyCategoryProcessHijack = 7, // Process hijacking related keys
    RegistryKeyCategoryDllHijack = 8,   // DLL hijacking related keys
    RegistryKeyCategoryComObjects = 9   // COM object registration keys
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
    LARGE_INTEGER ProcessCreateTime;     // When the process was created
    ULONG ProcessAgeSeconds;             // How long the process has been running
    BOOLEAN IsElevated;                  // Process running with admin rights
    ULONG SessionId;                     // Session ID of the process
    ULONG ProcessImageEntropy;           // Entropy of process image name (randomness measure)
    
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
    ULONG ProcessHijackKeysAccessed;     // Number of process hijacking keys accessed
    ULONG DllHijackKeysAccessed;         // Number of DLL hijacking keys accessed
    ULONG ComObjectKeysAccessed;         // Number of COM object keys accessed
    
    // Temporal patterns
    ULONG OperationBurstCount;           // Number of operation bursts
    ULONG MaxOperationsPerBurst;         // Maximum operations in a single burst
    ULONG BurstIntervalMs;               // Typical time interval between bursts
    ULONG OperationDensityPerMin;        // Operations per minute
    ULONG TimingVariance;                // Variance in timing between operations
    
    // Remote operations
    ULONG RemoteOperationCount;          // Operations performed by other processes
    
    // Suspicious indicators
    ULONG FileExtensionModificationCount; // Count of file extension modifications (ransomware indicator)
    ULONG SecuritySettingModificationCount; // Count of security setting changes
    ULONG WritesToReadsRatio;            // Ratio of write to read operations (scaled by 100)
    ULONG RegistryKeyDepthMax;           // Maximum depth of registry keys accessed
    ULONG RegistryValueEntropyAvg;       // Average entropy of registry values (scaled by 100)
    ULONG ComRegistryModifications;      // Modifications to COM registry keys
    ULONG CriticalSystemKeyModifications; // Modifications to critical system keys
    
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
    
    // Process information
    ULONG ProcessAgeSeconds;             // How long the process has been running
    ULONG ProcessImageEntropy;           // Entropy of process name/path
    ULONG SessionId;                     // Session ID
    BOOLEAN IsElevated;                  // Is process running with admin rights
    
    // Time metrics
    ULONGLONG FirstSeenTime;             // First operation timestamp (epoch time)
    ULONGLONG LastSeenTime;              // Last operation timestamp (epoch time)
    ULONGLONG OperationDurationSec;      // Total duration of operations
    ULONGLONG ProcessCreateTime;         // When process was created (epoch time)
    
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
    ULONG ProcessHijackKeysAccessed;
    ULONG DllHijackKeysAccessed;
    ULONG ComObjectKeysAccessed;
    
    // Temporal patterns
    ULONG OperationBurstCount;
    ULONG MaxOperationsPerBurst;
    ULONG BurstIntervalMs;
    ULONG OperationDensityPerMin;
    ULONG TimingVariance;
    
    // Remote operations
    ULONG RemoteOperationCount;
    
    // Suspicious indicators
    ULONG FileExtensionModificationCount;
    ULONG SecuritySettingModificationCount;
    ULONG WritesToReadsRatio;
    ULONG RegistryKeyDepthMax;
    ULONG RegistryValueEntropyAvg;
    ULONG ComRegistryModifications;
    ULONG CriticalSystemKeyModifications;
    
    // Reserved for future use
    ULONG Reserved[5];
} REGISTRY_FEATURE_VECTOR, *PREGISTRY_FEATURE_VECTOR;
