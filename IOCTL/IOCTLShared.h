#pragma once

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
    WCHAR UserName[64];
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

// Image load entry
typedef struct _IMAGE_LOAD_INFO {
    ULONG ProcessId;
    WCHAR ImagePath[MAX_PATH_LENGTH];
    ULONG_PTR ImageBase;
    SIZE_T ImageSize;
    BOOLEAN RemoteLoad;
    ULONG CallerProcessId;
    LARGE_INTEGER LoadTime;
} IMAGE_LOAD_INFO, *PIMAGE_LOAD_INFO;

typedef struct _IMAGE_LOAD_LIST {
    ULONG Count;
    IMAGE_LOAD_INFO LoadedImages[1]; // Variable length array
} IMAGE_LOAD_LIST, *PIMAGE_LOAD_LIST;

// Thread creation info
typedef struct _THREAD_INFO {
    ULONG ThreadId;
    ULONG ProcessId;
    ULONG CreatorProcessId;
    ULONG_PTR StartAddress;
    BOOLEAN IsRemoteThread;
    LARGE_INTEGER CreationTime;
} THREAD_INFO, *PTHREAD_INFO;

typedef struct _THREAD_LIST {
    ULONG Count;
    THREAD_INFO Threads[1]; // Variable length array
} THREAD_LIST, *PTHREAD_LIST;

// Alert types matching those in driver's DetectionLogic.h
typedef enum _ALERT_TYPE {
    AlertTypeStackViolation = 0,
    AlertTypeFilterViolation,
    AlertTypeRemoteThreadCreation,
    AlertTypeParentProcessIdSpoofing
} ALERT_TYPE;

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
