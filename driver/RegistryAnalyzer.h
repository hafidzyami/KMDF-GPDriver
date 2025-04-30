/*
 * Registry data analyzer for malware detection
 * Based on K-Means clustering research for registry behavior analysis
 */
#pragma once
#include "common.h"
#include "ObjectFilter.h"
#include "ImageFilter.h"
#include "registry_structures.h"

// Class definition with public interface
class RegistryAnalyzer
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
    
    ULONG CalculateKeyDepth(
        _In_ PUNICODE_STRING KeyPath
        );
    
    ULONG CalculateEntropy(
        _In_ PUCHAR Data,
        _In_ ULONG Size
        );
    
    BOOLEAN IsProcessElevated(
        _In_ HANDLE ProcessId
        );
    
    VOID UpdateProcessInformation(
        _Inout_ PPROCESS_REGISTRY_PROFILE Profile
        );
    
    ULONG CalculatePathEntropy(
        _In_ PUNICODE_STRING Path
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
};
