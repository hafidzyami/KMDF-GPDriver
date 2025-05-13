#pragma once
#include "shared.h"

//
// Shared IOCTL codes and structures between driver and client application
//

#define DEVICE_NAME L"\\\\.\\RegistryAnalyzer"

// Base IOCTL code
#define IOCTL_REGISTRY_ANALYZER_BASE      0x8000

// Existing IOCTL
#define IOCTL_EXPORT_REGISTRY_FEATURES_CSV CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_REGISTRY_ANALYZER_BASE + 1, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Informasi Proses
#define IOCTL_GET_PROCESS_LIST            CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_REGISTRY_ANALYZER_BASE + 2, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_PROCESS_DETAILS         CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_REGISTRY_ANALYZER_BASE + 3, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Informasi Registry
#define IOCTL_ADD_REGISTRY_FILTER         CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_REGISTRY_ANALYZER_BASE + 4, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_REGISTRY_ACTIVITY       CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_REGISTRY_ANALYZER_BASE + 5, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Monitoring Thread/DLL
#define IOCTL_GET_IMAGE_LOAD_HISTORY      CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_REGISTRY_ANALYZER_BASE + 6, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_THREAD_CREATION_HISTORY CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_REGISTRY_ANALYZER_BASE + 7, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Alert Management
#define IOCTL_GET_ALERTS                  CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_REGISTRY_ANALYZER_BASE + 8, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CLEAR_ALERTS                CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_REGISTRY_ANALYZER_BASE + 9, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Tamper Protection
#define IOCTL_PROTECT_PROCESS             CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_REGISTRY_ANALYZER_BASE + 10, METHOD_BUFFERED, FILE_ANY_ACCESS)

// System Statistics
#define IOCTL_GET_SYSTEM_STATS            CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_REGISTRY_ANALYZER_BASE + 11, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Maximum path length
#define MAX_PATH_LENGTH 260

// Process list structures
typedef struct _PROCESS_INFO {
    ULONG ProcessId;
    ULONG ParentProcessId;
    WCHAR ImagePath[MAX_PATH_LENGTH];
    WCHAR CommandLine[MAX_PATH_LENGTH];
    LARGE_INTEGER CreationTime;
    BOOLEAN IsTerminated;

    // Malware detection enhancements
    ULONG LoadedModuleCount;        // Total modules/DLLs loaded
    ULONG ThreadCount;              // Total threads
    BOOLEAN HasRemoteLoadedModules; // Any modules loaded by another process
    ULONG RemoteLoadCount;          // Number of remotely loaded modules
    WCHAR FirstRemoteModule[MAX_PATH_LENGTH]; // First remotely loaded module
    BOOLEAN HasRemoteCreatedThreads; // Any threads created by another process
    ULONG RemoteThreadCount;        // Number of remotely created threads
    ULONG FirstRemoteThreadCreator; // PID of first remote thread creator
    ULONG_PTR FirstRemoteThreadAddress; // Start address of first remote thread
    ULONG AnomalyScore;            // 0-100 score of how suspicious this process is
} PROCESS_INFO, *PPROCESS_INFO;

typedef struct _PROCESS_LIST {
    ULONG Count;
    PROCESS_INFO Processes[1]; // Variable length array
} PROCESS_LIST, *PPROCESS_LIST;

// Process details request structure
typedef struct _PROCESS_DETAILS_REQUEST {
    ULONG ProcessId;
} PROCESS_DETAILS_REQUEST, *PPROCESS_DETAILS_REQUEST;

// Registry filter structure
typedef struct _REGISTRY_FILTER {
    WCHAR RegistryPath[MAX_PATH_LENGTH];
    ULONG FilterFlags;  // FILTER_FLAG_READ, FILTER_FLAG_WRITE, FILTER_FLAG_DELETE
} REGISTRY_FILTER, *PREGISTRY_FILTER;

// Registry activity entry
typedef struct _REGISTRY_ACTIVITY {
    ULONG ProcessId;
    ULONG OperationType;  // Read, Write, Delete, etc.
    WCHAR RegistryPath[MAX_PATH_LENGTH];
    WCHAR ProcessName[MAX_PATH_LENGTH];
    LARGE_INTEGER Timestamp;
} REGISTRY_ACTIVITY, *PREGISTRY_ACTIVITY;

typedef struct _REGISTRY_ACTIVITY_LIST {
    ULONG Count;
    REGISTRY_ACTIVITY Activities[1]; // Variable length array
} REGISTRY_ACTIVITY_LIST, *PREGISTRY_ACTIVITY_LIST;

// Flags for IMAGE_LOAD_INFO
#define IMAGE_FLAG_REMOTE_LOADED        0x0001
#define IMAGE_FLAG_NON_SYSTEM           0x0002
#define IMAGE_FLAG_SUSPICIOUS_LOCATION  0x0004
#define IMAGE_FLAG_POTENTIAL_HIJACK     0x0008
#define IMAGE_FLAG_NETWORK_RELATED      0x0010
#define IMAGE_FLAG_HOOK_RELATED         0x0020
#define IMAGE_FLAG_UNSIGNED             0x0040

// Enhanced IMAGE_LOAD_INFO structure
typedef struct _IMAGE_LOAD_INFO {
    ULONG ProcessId;
    WCHAR ImagePath[MAX_PATH_LENGTH];
    ULONG_PTR ImageBase;
    SIZE_T ImageSize;
    BOOLEAN RemoteLoad;
    ULONG CallerProcessId;
    LARGE_INTEGER LoadTime;
    ULONG Flags;  // Added flags field
    ULONG RiskLevel; // 0=None, 1=Low, 2=Medium, 3=High
} IMAGE_LOAD_INFO, *PIMAGE_LOAD_INFO;

typedef struct _IMAGE_LOAD_LIST {
    ULONG Count;
    IMAGE_LOAD_INFO LoadedImages[1]; // Variable length array
} IMAGE_LOAD_LIST, *PIMAGE_LOAD_LIST;

#define THREAD_FLAG_REMOTE_CREATED       0x0001
#define THREAD_FLAG_SUSPICIOUS_ADDRESS   0x0002
#define THREAD_FLAG_NOT_IN_IMAGE         0x0004
#define THREAD_FLAG_SUSPICIOUS_TIMING    0x0008
#define THREAD_FLAG_SUSPENDED            0x0010
#define THREAD_FLAG_INJECTION_PATTERN    0x0020

// Enhanced THREAD_INFO structure
typedef struct _THREAD_INFO {
    ULONG ThreadId;
    ULONG ProcessId;
    ULONG CreatorProcessId;
    ULONG_PTR StartAddress;
    BOOLEAN IsRemoteThread;
    LARGE_INTEGER CreationTime;
    ULONG Flags;  // Added flags field
    ULONG RiskLevel; // 0=None, 1=Low, 2=Medium, 3=High
} THREAD_INFO, *PTHREAD_INFO;

typedef struct _THREAD_LIST {
    ULONG Count;
    THREAD_INFO Threads[1]; // Variable length array
} THREAD_LIST, *PTHREAD_LIST;

// Alert info structure
typedef struct _ALERT_INFO {
    ULONG AlertId;
    ALERT_TYPE Type;
    ULONG SourceProcessId;
    WCHAR SourcePath[MAX_PATH_LENGTH];
    WCHAR TargetPath[MAX_PATH_LENGTH];
    LARGE_INTEGER Timestamp;
    ULONG_PTR ViolatingAddress;  // For stack violations
    ULONG TargetProcessId;       // For remote operations
} ALERT_INFO, *PALERT_INFO;

typedef struct _ALERT_LIST {
    ULONG Count;
    ALERT_INFO Alerts[1]; // Variable length array
} ALERT_LIST, *PALERT_LIST;

// Process protection request
typedef struct _PROCESS_PROTECTION_REQUEST {
    ULONG ProcessId;
    BOOLEAN Enable;  // TRUE to enable protection, FALSE to disable
} PROCESS_PROTECTION_REQUEST, *PPROCESS_PROTECTION_REQUEST;

// System statistics
typedef struct _SYSTEM_STATS {
    ULONG TotalProcessesMonitored;
    ULONG ActiveProcesses;
    ULONG TotalAlertsGenerated;
    ULONG PendingAlerts;
    ULONG RegistryOperationsBlocked;
    ULONG RegistryFiltersCount;
    ULONG ThreadsMonitored;
    ULONG RemoteThreadsDetected;
    ULONG ImagesMonitored;
    ULONG RemoteImagesDetected;
    SIZE_T DriverMemoryUsage;
    LARGE_INTEGER DriverUptime;
} SYSTEM_STATS, *PSYSTEM_STATS;
