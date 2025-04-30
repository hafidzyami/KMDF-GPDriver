/*
 * Registry data analyzer for malware detection
 * Based on K-Means clustering research for registry behavior analysis
 */
#include "pch.h"
#include "RegistryAnalyzer.h"

// Sensitive registry key prefixes for categorization
const WCHAR* AutorunKeyPrefixes[] = {
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    L"\\REGISTRY\\USER\\S-1-5-21-*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    L"\\REGISTRY\\USER\\S-1-5-21-*\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved",
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
};

const WCHAR* SecurityKeyPrefixes[] = {
    L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy",
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows Defender",
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender",
    L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\SecurityHealthService",
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Security Center"
};

const WCHAR* FileAssocKeyPrefixes[] = {
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Classes\\",
    L"\\REGISTRY\\USER\\S-1-5-21-*\\Software\\Classes\\"
};

const WCHAR* NetworkKeyPrefixes[] = {
    L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip",
    L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Dnscache",
    L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Winsock"
};

const WCHAR* ServiceKeyPrefixes[] = {
    L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\"
};

const WCHAR* SensitiveKeyPrefixes[] = {
    L"\\REGISTRY\\MACHINE\\SAM",
    L"\\REGISTRY\\MACHINE\\SECURITY",
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Cryptography",
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
    L"\\REGISTRY\\USER\\S-1-5-21-*\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies"
};

/**
    Initialize the registry analyzer.
*/
RegistryAnalyzer::RegistryAnalyzer()
{
    // Initialize the process profile list
    InitializeListHead(&ProcessProfileListHead);
    FltInitializePushLock(&ProcessProfileLock);
    ProfileCount = 0;
    
    // Initialize the key category table
    RtlZeroMemory(&KeyCategoryTable, sizeof(KeyCategoryTable));
    
    // Initialize the key category table - would initialize AVL table here
    // but we'll use a simpler approach for categorization for now
}

/**
    Cleanup the registry analyzer.
*/
RegistryAnalyzer::~RegistryAnalyzer()
{
    PPROCESS_REGISTRY_PROFILE currentProfile;
    
    // Acquire exclusive lock on profile list
    FltAcquirePushLockExclusive(&ProcessProfileLock);
    
    // Free all profiles in the list
    while (!IsListEmpty(&ProcessProfileListHead))
    {
        currentProfile = CONTAINING_RECORD(RemoveHeadList(&ProcessProfileListHead), PROCESS_REGISTRY_PROFILE, ListEntry);
        FreeProcessProfile(currentProfile);
    }
    
    // Release lock
    FltReleasePushLock(&ProcessProfileLock);
    
    // Delete the lock
    FltDeletePushLock(&ProcessProfileLock);
}

/**
    Record a registry event and update profiles.
    @param ProcessId - The process ID performing the registry operation
    @param NotifyClass - Registry notification class
    @param RegistryObject - Registry key object
    @param ValueName - Registry value name
    @param DataBuffer - Data buffer for the operation
    @param DataSize - Size of the data buffer
    @param ValueType - Type of registry value
    @return NTSTATUS value indicating success or failure
*/
NTSTATUS 
RegistryAnalyzer::RecordRegistryEvent(
    _In_ HANDLE ProcessId,
    _In_ REG_NOTIFY_CLASS NotifyClass,
    _In_ PVOID RegistryObject,
    _In_ PUNICODE_STRING ValueName,
    _In_ PVOID DataBuffer,
    _In_ ULONG DataSize,
    _In_ ULONG ValueType
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    PREGISTRY_EVENT_DATA newEvent = NULL;
    PPROCESS_REGISTRY_PROFILE profile = NULL;
    HANDLE keyHandle = NULL;
    PKEY_NAME_INFORMATION keyNameInfo = NULL;
    ULONG keyNameInfoSize = 0;
    PUNICODE_STRING processName = NULL;
    REGISTRY_KEY_CATEGORY keyCategory;
    // REGISTRY_OPERATION_TYPE opType; // Unused variable removed
    LARGE_INTEGER currentTime;
    
    // Get current time
    KeQuerySystemTime(&currentTime);
    
    // Allocate memory for the new event
    newEvent = (PREGISTRY_EVENT_DATA)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(REGISTRY_EVENT_DATA), REGISTRY_EVENT_TAG);
    if (newEvent == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }
    
    RtlZeroMemory(newEvent, sizeof(REGISTRY_EVENT_DATA));
    
    // Basic event info
    newEvent->ProcessId = ProcessId;
    newEvent->ThreadId = PsGetCurrentThreadId();
    newEvent->Timestamp = currentTime;
    newEvent->NotifyClass = NotifyClass;
    newEvent->OperationType = MapNotifyClassToOperationType(NotifyClass);
    newEvent->ValueType = ValueType;
    newEvent->ValueSize = DataSize;
    newEvent->IsRemoteOperation = (PsGetCurrentProcessId() != ProcessId);
    newEvent->ParentProcessId = 0; // Will be filled later if needed
    
    // Get process name
    if (ImageFilter::GetProcessImageFileName(ProcessId, &processName)) {
        newEvent->ProcessName = processName;
    }
    
    // Copy value name if provided
    if (ValueName && ValueName->Length > 0 && ValueName->Buffer) {
        newEvent->ValueName = (PUNICODE_STRING)ExAllocatePool2(POOL_FLAG_NON_PAGED, 
                                                              sizeof(UNICODE_STRING) + ValueName->Length + sizeof(WCHAR),
                                                              REGISTRY_EVENT_TAG);
        if (newEvent->ValueName) {
            newEvent->ValueName->Buffer = (PWCH)((ULONG_PTR)newEvent->ValueName + sizeof(UNICODE_STRING));
            newEvent->ValueName->Length = ValueName->Length;
            newEvent->ValueName->MaximumLength = ValueName->Length + sizeof(WCHAR);
            RtlCopyMemory(newEvent->ValueName->Buffer, ValueName->Buffer, ValueName->Length);
            // Null terminate
            *(PWCHAR)((ULONG_PTR)newEvent->ValueName->Buffer + ValueName->Length) = L'\0';
        }
    }
    
    // Get full key path
    status = ObOpenObjectByPointer(RegistryObject, OBJ_KERNEL_HANDLE, NULL, KEY_READ, *CmKeyObjectType, KernelMode, &keyHandle);
    if (NT_SUCCESS(status)) {
        // First get the required size
        status = ZwQueryKey(keyHandle, KeyNameInformation, NULL, 0, &keyNameInfoSize);
        if (status == STATUS_BUFFER_TOO_SMALL || status == STATUS_BUFFER_OVERFLOW) {
            keyNameInfoSize += 32;  // Add some padding
            keyNameInfo = (PKEY_NAME_INFORMATION)ExAllocatePool2(POOL_FLAG_NON_PAGED, keyNameInfoSize, REGISTRY_EVENT_TAG);
            
            if (keyNameInfo) {
                status = ZwQueryKey(keyHandle, KeyNameInformation, keyNameInfo, keyNameInfoSize, &keyNameInfoSize);
                if (NT_SUCCESS(status)) {
                    // Allocate and setup key path
                    newEvent->KeyPath = (PUNICODE_STRING)ExAllocatePool2(POOL_FLAG_NON_PAGED,
                                                                        sizeof(UNICODE_STRING) + keyNameInfo->NameLength + sizeof(WCHAR),
                                                                        REGISTRY_EVENT_TAG);
                    if (newEvent->KeyPath) {
                        newEvent->KeyPath->Buffer = (PWCH)((ULONG_PTR)newEvent->KeyPath + sizeof(UNICODE_STRING));
                        newEvent->KeyPath->Length = (USHORT)keyNameInfo->NameLength;
                        newEvent->KeyPath->MaximumLength = (USHORT)(keyNameInfo->NameLength + sizeof(WCHAR));
                        RtlCopyMemory(newEvent->KeyPath->Buffer, keyNameInfo->Name, keyNameInfo->NameLength);
                        // Null terminate
                        *(PWCHAR)((ULONG_PTR)newEvent->KeyPath->Buffer + keyNameInfo->NameLength) = L'\0';
                    }
                }
                ExFreePool(keyNameInfo);
            }
        }
        ZwClose(keyHandle);
    }
    
    // Categorize the registry key
    if (newEvent->KeyPath) {
        keyCategory = CategorizeRegistryKey(newEvent->KeyPath);
        newEvent->KeyCategory = keyCategory;
    }
    
    // Only store data if it's small enough (to avoid excessive memory usage)
    if (DataBuffer && DataSize > 0 && DataSize <= 1024) {  // Limit to 1KB
        newEvent->DataBuffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, DataSize, REGISTRY_EVENT_TAG);
        if (newEvent->DataBuffer) {
            RtlCopyMemory(newEvent->DataBuffer, DataBuffer, DataSize);
            newEvent->DataBufferSize = DataSize;
        }
    }
    
    // Find or create a profile for this process
    profile = FindOrCreateProcessProfile(ProcessId);
    if (profile == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }
    
    // Update profile with this event
    FltAcquirePushLockExclusive(&profile->EventLock);
    
    // Update basic statistics
    profile->TotalOperationCount++;
    
    // Update operation type counts
    switch (newEvent->OperationType) {
        case RegistryOperationCreate:
            profile->CreateOperationCount++;
            break;
        case RegistryOperationModify:
            profile->ModifyOperationCount++;
            break;
        case RegistryOperationDelete:
            profile->DeleteOperationCount++;
            break;
        case RegistryOperationQuery:
            profile->QueryOperationCount++;
            break;
    }
    
    // Update key access statistics
    if (newEvent->KeyPath) {
        UpdateKeyAccessStats(profile, newEvent->KeyCategory);
    }
    
    // Update remote operation count
    if (newEvent->IsRemoteOperation) {
        profile->RemoteOperationCount++;
    }
    
    // Check for file extension modifications (potential ransomware indicator)
    if (newEvent->KeyPath && newEvent->OperationType == RegistryOperationModify && 
        newEvent->KeyCategory == RegistryKeyCategoryFileAssoc) {
        profile->FileExtensionModificationCount++;
    }
    
    // Check for security setting modifications
    if (newEvent->KeyPath && newEvent->OperationType != RegistryOperationQuery && 
        newEvent->KeyCategory == RegistryKeyCategorySecurity) {
        profile->SecuritySettingModificationCount++;
    }
    
    // Check for burst patterns
    CheckBurstPattern(profile, currentTime);
    
    // Update timestamp
    profile->LastSeen = currentTime;
    if (profile->FirstSeen.QuadPart == 0) {
        profile->FirstSeen = currentTime;
    }
    
    // Add the event to the list
    InsertTailList(&profile->EventList, &newEvent->ListEntry);
    profile->EventCount++;
    
    // Cleanup old events if we have too many
    if (profile->EventCount > 1000) {  // Keep at most 1000 events per process
        CleanupOldEvents(profile, 500);  // Keep the 500 most recent events
    }
    
    FltReleasePushLock(&profile->EventLock);
    
    // Success, don't free the event
    newEvent = NULL;
    
Exit:
    if (newEvent) {
        FreeRegistryEvent(newEvent);
    }
    
    return status;
}

/**
    Map registry notification class to operation type.
    @param NotifyClass - Registry notification class
    @return Registry operation type
*/
REGISTRY_OPERATION_TYPE 
RegistryAnalyzer::MapNotifyClassToOperationType(
    _In_ REG_NOTIFY_CLASS NotifyClass
    )
{
    switch (NotifyClass) {
        case RegNtPreCreateKey:
        case RegNtPreCreateKeyEx:
            return RegistryOperationCreate;
            
        case RegNtPreSetValueKey:
        case RegNtPreSetInformationKey:
            return RegistryOperationModify;
            
        case RegNtPreDeleteKey:
        case RegNtPreDeleteValueKey:
            return RegistryOperationDelete;
            
        case RegNtPreQueryKey:
        case RegNtPreQueryValueKey:
        case RegNtPreEnumerateKey:
        case RegNtPreEnumerateValueKey:
            return RegistryOperationQuery;
            
        default:
            return RegistryOperationUnknown;
    }
}

/**
    Categorize a registry key based on its path.
    @param KeyPath - Registry key path
    @return Registry key category
*/
REGISTRY_KEY_CATEGORY 
RegistryAnalyzer::CategorizeRegistryKey(
    _In_ PUNICODE_STRING KeyPath
    )
{
    // UNICODE_STRING tempString; // Unused variable removed
    UNICODE_STRING prefixString;
    
    if (!KeyPath || !KeyPath->Buffer) {
        return RegistryKeyCategoryNormal;
    }
    
    // Check autorun keys
    for (ULONG i = 0; i < ARRAYSIZE(AutorunKeyPrefixes); i++) {
        RtlInitUnicodeString(&prefixString, AutorunKeyPrefixes[i]);
        if (RtlPrefixUnicodeString(&prefixString, KeyPath, TRUE)) {
            return RegistryKeyCategoryAutorun;
        }
    }
    
    // Check security keys
    for (ULONG i = 0; i < ARRAYSIZE(SecurityKeyPrefixes); i++) {
        RtlInitUnicodeString(&prefixString, SecurityKeyPrefixes[i]);
        if (RtlPrefixUnicodeString(&prefixString, KeyPath, TRUE)) {
            return RegistryKeyCategorySecurity;
        }
    }
    
    // Check file association keys
    for (ULONG i = 0; i < ARRAYSIZE(FileAssocKeyPrefixes); i++) {
        RtlInitUnicodeString(&prefixString, FileAssocKeyPrefixes[i]);
        if (RtlPrefixUnicodeString(&prefixString, KeyPath, TRUE)) {
            return RegistryKeyCategoryFileAssoc;
        }
    }
    
    // Check network keys
    for (ULONG i = 0; i < ARRAYSIZE(NetworkKeyPrefixes); i++) {
        RtlInitUnicodeString(&prefixString, NetworkKeyPrefixes[i]);
        if (RtlPrefixUnicodeString(&prefixString, KeyPath, TRUE)) {
            return RegistryKeyCategoryNetworking;
        }
    }
    
    // Check service keys
    for (ULONG i = 0; i < ARRAYSIZE(ServiceKeyPrefixes); i++) {
        RtlInitUnicodeString(&prefixString, ServiceKeyPrefixes[i]);
        if (RtlPrefixUnicodeString(&prefixString, KeyPath, TRUE)) {
            return RegistryKeyCategoryServices;
        }
    }
    
    // Check sensitive keys
    for (ULONG i = 0; i < ARRAYSIZE(SensitiveKeyPrefixes); i++) {
        RtlInitUnicodeString(&prefixString, SensitiveKeyPrefixes[i]);
        if (RtlPrefixUnicodeString(&prefixString, KeyPath, TRUE)) {
            return RegistryKeyCategorySensitive;
        }
    }
    
    // Default category
    return RegistryKeyCategoryNormal;
}

/**
    Find an existing process profile or create a new one.
    @param ProcessId - Process ID
    @return Process registry profile or NULL on failure
*/
PPROCESS_REGISTRY_PROFILE 
RegistryAnalyzer::FindOrCreateProcessProfile(
    _In_ HANDLE ProcessId
    )
{
    PPROCESS_REGISTRY_PROFILE profile = NULL;
    PLIST_ENTRY entry;
    BOOLEAN found = FALSE;
    
    // First look for an existing profile
    FltAcquirePushLockShared(&ProcessProfileLock);
    
    for (entry = ProcessProfileListHead.Flink; entry != &ProcessProfileListHead; entry = entry->Flink) {
        profile = CONTAINING_RECORD(entry, PROCESS_REGISTRY_PROFILE, ListEntry);
        if (profile->ProcessId == ProcessId) {
            found = TRUE;
            break;
        }
    }
    
    FltReleasePushLock(&ProcessProfileLock);
    
    // If not found, create a new profile
    if (!found) {
        profile = (PPROCESS_REGISTRY_PROFILE)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(PROCESS_REGISTRY_PROFILE), REGISTRY_PROFILE_TAG);
        if (profile) {
            RtlZeroMemory(profile, sizeof(PROCESS_REGISTRY_PROFILE));
            
            profile->ProcessId = ProcessId;
            InitializeListHead(&profile->EventList);
            FltInitializePushLock(&profile->EventLock);
            
            // Get process name and path
            ImageFilter::GetProcessImageFileName(ProcessId, &profile->ProcessPath);
            if (profile->ProcessPath != NULL) {
                // Extract just the process name from the path for easy access
                profile->ProcessName = profile->ProcessPath;
            }
            
            // Add to the list
            FltAcquirePushLockExclusive(&ProcessProfileLock);
            InsertTailList(&ProcessProfileListHead, &profile->ListEntry);
            ProfileCount++;
            FltReleasePushLock(&ProcessProfileLock);
        }
    }
    
    return profile;
}

/**
    Check for burst patterns in registry operations.
    @param Profile - Process registry profile
    @param CurrentTime - Current timestamp
    @return TRUE if burst detected, FALSE otherwise
*/
BOOLEAN 
RegistryAnalyzer::CheckBurstPattern(
    _Inout_ PPROCESS_REGISTRY_PROFILE Profile,
    _In_ LARGE_INTEGER CurrentTime
    )
{
    static const LONGLONG BURST_THRESHOLD = 10 * 10000000; // 10 seconds in 100ns intervals
    static const ULONG MIN_OPS_FOR_BURST = 20; // Minimum operations to consider a burst
    
    LONGLONG timeDiff;
    static LONGLONG lastBurstTime = 0;
    static ULONG opsSinceLastBurst = 0;
    
    // Check if enough time has passed since last operation
    if (Profile->LastSeen.QuadPart != 0) {
        timeDiff = CurrentTime.QuadPart - Profile->LastSeen.QuadPart;
        
        // If we've been silent for a while, this could be the start of a new burst
        if (timeDiff > BURST_THRESHOLD) {
            // If we had enough operations since last burst, count it
            if (opsSinceLastBurst >= MIN_OPS_FOR_BURST) {
                Profile->OperationBurstCount++;
                if (opsSinceLastBurst > Profile->MaxOperationsPerBurst) {
                    Profile->MaxOperationsPerBurst = opsSinceLastBurst;
                }
                
                // Calculate average interval between bursts
                if (lastBurstTime != 0) {
                    LONGLONG burstInterval = (Profile->LastSeen.QuadPart - lastBurstTime) / 10000; // Convert to milliseconds
                    if (Profile->BurstIntervalMs == 0) {
                        Profile->BurstIntervalMs = (ULONG)burstInterval;
                    } else {
                        // Moving average
                        Profile->BurstIntervalMs = (Profile->BurstIntervalMs * 3 + (ULONG)burstInterval) / 4;
                    }
                }
                
                lastBurstTime = CurrentTime.QuadPart;
                opsSinceLastBurst = 0;
                return TRUE;
            }
            
            // Reset counter for new burst
            opsSinceLastBurst = 1;
        } else {
            // Still within the same burst
            opsSinceLastBurst++;
        }
    }
    
    return FALSE;
}

/**
    Update key access statistics based on key category.
    @param Profile - Process registry profile
    @param KeyCategory - Registry key category
*/
VOID 
RegistryAnalyzer::UpdateKeyAccessStats(
    _Inout_ PPROCESS_REGISTRY_PROFILE Profile,
    _In_ REGISTRY_KEY_CATEGORY KeyCategory
    )
{
    // Increment category-specific counters
    switch (KeyCategory) {
        case RegistryKeyCategoryAutorun:
            Profile->AutorunKeysAccessed++;
            break;
            
        case RegistryKeyCategorySecurity:
            Profile->SecurityKeysAccessed++;
            break;
            
        case RegistryKeyCategoryFileAssoc:
            Profile->FileAssocKeysAccessed++;
            break;
            
        case RegistryKeyCategoryNetworking:
            Profile->NetworkingKeysAccessed++;
            break;
            
        case RegistryKeyCategoryServices:
            Profile->ServicesKeysAccessed++;
            break;
            
        case RegistryKeyCategorySensitive:
            Profile->SensitiveKeysAccessed++;
            break;
    }
    
    // Increment unique keys counter - in a real implementation,
    // we would check if this key path has been seen before
    Profile->UniqueKeysAccessed++;
}

/**
    Clean up old events to manage memory usage.
    @param Profile - Process registry profile
    @param MaxEventsToKeep - Maximum number of events to keep
*/
VOID 
RegistryAnalyzer::CleanupOldEvents(
    _Inout_ PPROCESS_REGISTRY_PROFILE Profile,
    _In_ ULONG MaxEventsToKeep
    )
{
    PREGISTRY_EVENT_DATA oldestEvent;
    
    while (Profile->EventCount > MaxEventsToKeep && !IsListEmpty(&Profile->EventList)) {
        oldestEvent = CONTAINING_RECORD(RemoveHeadList(&Profile->EventList), REGISTRY_EVENT_DATA, ListEntry);
        FreeRegistryEvent(oldestEvent);
        Profile->EventCount--;
    }
}

/**
    Free resources associated with a registry event.
    @param Event - Registry event data to free
*/
VOID 
RegistryAnalyzer::FreeRegistryEvent(
    _In_ PREGISTRY_EVENT_DATA Event
    )
{
    if (Event) {
        // Free allocated string buffers
        if (Event->KeyPath) {
            ExFreePool(Event->KeyPath);
        }
        
        if (Event->ValueName) {
            ExFreePool(Event->ValueName);
        }
        
        if (Event->ProcessName) {
            ExFreePool(Event->ProcessName);
        }
        
        // Free data buffer if allocated
        if (Event->DataBuffer) {
            ExFreePool(Event->DataBuffer);
        }
        
        // Free the event structure itself
        ExFreePool(Event);
    }
}

/**
    Free resources associated with a process profile.
    @param Profile - Process registry profile to free
*/
VOID 
RegistryAnalyzer::FreeProcessProfile(
    _In_ PPROCESS_REGISTRY_PROFILE Profile
    )
{
    PREGISTRY_EVENT_DATA event;
    
    if (Profile) {
        // Free all events in the list
        FltAcquirePushLockExclusive(&Profile->EventLock);
        
        while (!IsListEmpty(&Profile->EventList)) {
            event = CONTAINING_RECORD(RemoveHeadList(&Profile->EventList), REGISTRY_EVENT_DATA, ListEntry);
            FreeRegistryEvent(event);
        }
        
        FltReleasePushLock(&Profile->EventLock);
        FltDeletePushLock(&Profile->EventLock);
        
        // Free process name and path
        if (Profile->ProcessPath) {
            ExFreePool(Profile->ProcessPath);
        }
        
        // Free the profile structure itself
        ExFreePool(Profile);
    }
}

/**
    Get the number of process profiles being tracked.
    @return Number of profiles
*/
ULONG 
RegistryAnalyzer::GetProcessProfileCount()
{
    return ProfileCount;
}

/**
    Export feature vectors for use in user-mode clustering.
    @param FeatureVectors - Buffer to receive feature vectors
    @param MaxFeatureVectors - Maximum number of vectors to export
    @param ActualFeatureVectors - Actual number of vectors exported
    @return NTSTATUS value indicating success or failure
*/
NTSTATUS 
RegistryAnalyzer::ExportFeatureVectors(
    _Out_ PREGISTRY_FEATURE_VECTOR FeatureVectors,
    _In_ ULONG MaxFeatureVectors,
    _Out_ PULONG ActualFeatureVectors
    )
{
    PPROCESS_REGISTRY_PROFILE profile;
    PLIST_ENTRY entry;
    ULONG count = 0;
    LARGE_INTEGER localTime;
    
    // Initialize output count and output buffer
    *ActualFeatureVectors = 0;
    
    // Check parameters
    if (!FeatureVectors || MaxFeatureVectors == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    
    // Zero out the buffer to ensure it's initialized
    RtlZeroMemory(FeatureVectors, MaxFeatureVectors * sizeof(REGISTRY_FEATURE_VECTOR));

    
    // Acquire shared lock to iterate profiles
    FltAcquirePushLockShared(&ProcessProfileLock);
    
    // Iterate through profiles and fill feature vectors
    for (entry = ProcessProfileListHead.Flink; 
         entry != &ProcessProfileListHead && count < MaxFeatureVectors; 
         entry = entry->Flink)
    {
        profile = CONTAINING_RECORD(entry, PROCESS_REGISTRY_PROFILE, ListEntry);
        
        // Skip profiles with very few operations
        if (profile->TotalOperationCount < 5) {
            continue;
        }
        
        // Ensure we don't exceed the provided buffer
        if (count >= MaxFeatureVectors) {
            // We've exceeded the buffer size, stop processing
            break;
        }
        
        // Process this profile and populate feature vector
        // Fill feature vector
        RtlZeroMemory(&FeatureVectors[count], sizeof(REGISTRY_FEATURE_VECTOR));
        
        // Basic identification
        FeatureVectors[count].ProcessId = profile->ProcessId;
        
        // Copy process name if available
        if (profile->ProcessName && profile->ProcessName->Buffer) {
            RtlStringCchCopyW(FeatureVectors[count].ProcessName, MAX_PATH, profile->ProcessName->Buffer);
        }
        
        // Time metrics
        ExSystemTimeToLocalTime(&profile->FirstSeen, &localTime);
        FeatureVectors[count].FirstSeenTime = localTime.QuadPart / 10000000ULL - 11644473600ULL; // Convert to Unix epoch
        
        ExSystemTimeToLocalTime(&profile->LastSeen, &localTime);
        FeatureVectors[count].LastSeenTime = localTime.QuadPart / 10000000ULL - 11644473600ULL; // Convert to Unix epoch
        
        if (profile->FirstSeen.QuadPart != 0 && profile->LastSeen.QuadPart != 0) {
            FeatureVectors[count].OperationDurationSec = 
                (profile->LastSeen.QuadPart - profile->FirstSeen.QuadPart) / 10000000ULL;
        }
        
        // Operation counts
        FeatureVectors[count].TotalOperationCount = profile->TotalOperationCount;
        FeatureVectors[count].CreateOperationCount = profile->CreateOperationCount;
        FeatureVectors[count].ModifyOperationCount = profile->ModifyOperationCount;
        FeatureVectors[count].DeleteOperationCount = profile->DeleteOperationCount;
        FeatureVectors[count].QueryOperationCount = profile->QueryOperationCount;
        
        // Key access patterns
        FeatureVectors[count].UniqueKeysAccessed = profile->UniqueKeysAccessed;
        FeatureVectors[count].AutorunKeysAccessed = profile->AutorunKeysAccessed;
        FeatureVectors[count].SecurityKeysAccessed = profile->SecurityKeysAccessed;
        FeatureVectors[count].FileAssocKeysAccessed = profile->FileAssocKeysAccessed;
        FeatureVectors[count].NetworkingKeysAccessed = profile->NetworkingKeysAccessed;
        FeatureVectors[count].ServicesKeysAccessed = profile->ServicesKeysAccessed;
        FeatureVectors[count].SensitiveKeysAccessed = profile->SensitiveKeysAccessed;
        
        // Burst metrics
        FeatureVectors[count].OperationBurstCount = profile->OperationBurstCount;
        FeatureVectors[count].MaxOperationsPerBurst = profile->MaxOperationsPerBurst;
        FeatureVectors[count].BurstIntervalMs = profile->BurstIntervalMs;
        
        // Remote operations
        FeatureVectors[count].RemoteOperationCount = profile->RemoteOperationCount;
        
        // Suspicious indicators
        FeatureVectors[count].FileExtensionModificationCount = profile->FileExtensionModificationCount;
        FeatureVectors[count].SecuritySettingModificationCount = profile->SecuritySettingModificationCount;
        
        // Increment counter only after successful processing
        count++;
    }
    
    FltReleasePushLock(&ProcessProfileLock);
    
    *ActualFeatureVectors = count;
    return STATUS_SUCCESS;
}

/**
    Clean up old profiles to manage memory usage.
    @param CutoffTime - Time threshold for cleanup
*/
VOID 
RegistryAnalyzer::CleanupOldProfiles(
    _In_ LARGE_INTEGER CutoffTime
    )
{
    PPROCESS_REGISTRY_PROFILE profile;
    PLIST_ENTRY entry, nextEntry;
    
    // Acquire exclusive lock to modify profile list
    FltAcquirePushLockExclusive(&ProcessProfileLock);
    
    // Iterate through profiles and remove old ones
    for (entry = ProcessProfileListHead.Flink; entry != &ProcessProfileListHead;) {
        // Save next entry in case we remove this one
        nextEntry = entry->Flink;
        
        profile = CONTAINING_RECORD(entry, PROCESS_REGISTRY_PROFILE, ListEntry);
        
        // Check if profile is old
        if (profile->LastSeen.QuadPart < CutoffTime.QuadPart) {
            // Remove from list
            RemoveEntryList(entry);
            
            // Free the profile
            FreeProcessProfile(profile);
            
            // Decrement count
            if (ProfileCount > 0) {
                ProfileCount--;
            }
        }
        
        // Move to next entry
        entry = nextEntry;
    }
    
    // Release lock
    FltReleasePushLock(&ProcessProfileLock);
}

/**
    Export feature vectors to a CSV buffer in format ready for saving.
    @param CSVBuffer - Buffer to receive CSV data
    @param BufferSize - Size of the buffer
    @param ActualSize - Actual size of CSV data written
    @return NTSTATUS value indicating success or failure
*/
NTSTATUS 
RegistryAnalyzer::ExportFeatureVectorsToCSVBuffer(
    _Out_ PUCHAR CSVBuffer,
    _In_ ULONG BufferSize,
    _Out_ PULONG ActualSize
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    PREGISTRY_FEATURE_VECTOR featureVectors = NULL;
    ULONG featureVectorCount = 0;
    ULONG requiredBufferSize = 0;
    ULONG currentOffset = 0;
    ULONG bytesWritten = 0;
    // Variables for CSV formatting
    
    // Initialize output parameters
    *ActualSize = 0;
    
    // Ensure buffer is initialized if provided
    if (CSVBuffer && BufferSize > 0) {
        RtlZeroMemory(CSVBuffer, BufferSize);
    }
    
    // Get number of feature vectors
    featureVectorCount = 0;
    FltAcquirePushLockShared(&ProcessProfileLock);
    
    // Count profiles with sufficient operations
    PLIST_ENTRY entry;
    PPROCESS_REGISTRY_PROFILE profile;
    
    for (entry = ProcessProfileListHead.Flink; 
         entry != &ProcessProfileListHead; 
         entry = entry->Flink)
    {
        profile = CONTAINING_RECORD(entry, PROCESS_REGISTRY_PROFILE, ListEntry);
        if (profile->TotalOperationCount >= 5) {
            featureVectorCount++;
        }
    }
    
    FltReleasePushLock(&ProcessProfileLock);
    
    // If no profiles or buffer size is zero, return empty but initialize buffer
    if (featureVectorCount == 0 || BufferSize == 0) {
        *ActualSize = 0;
        // Initialize buffer with zero even if empty
        if (BufferSize > 0) {
            RtlZeroMemory(CSVBuffer, BufferSize);
        }
        return STATUS_SUCCESS;
    }
    
    // Allocate memory for feature vectors
    featureVectors = (PREGISTRY_FEATURE_VECTOR)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, 
        featureVectorCount * sizeof(REGISTRY_FEATURE_VECTOR),
        REGISTRY_FEATURE_TAG);
    
    if (featureVectors == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    // Get feature vectors
    ULONG actualCount = 0;
    status = this->ExportFeatureVectors(featureVectors, featureVectorCount, &actualCount);
    
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(featureVectors, REGISTRY_FEATURE_TAG);
        return status;
    }
    
    // Start building CSV
    // First write CSV header
    CHAR csvHeader[] = "ProcessId,ProcessName,FirstSeenTime,LastSeenTime,OperationDurationSec,"
                      "TotalOperationCount,CreateOperationCount,ModifyOperationCount,DeleteOperationCount,QueryOperationCount,"
                      "UniqueKeysAccessed,AutorunKeysAccessed,SecurityKeysAccessed,FileAssocKeysAccessed,"
                      "NetworkingKeysAccessed,ServicesKeysAccessed,SensitiveKeysAccessed,"
                      "OperationBurstCount,MaxOperationsPerBurst,BurstIntervalMs,"
                      "RemoteOperationCount,FileExtensionModificationCount,SecuritySettingModificationCount\r\n";
    
    requiredBufferSize = (ULONG)strlen(csvHeader);
    
    // Calculate required buffer size
    for (ULONG i = 0; i < actualCount; i++) {
        // Conservative estimate: 25 bytes per numeric field (24 fields) + process name (MAX_PATH) + commas and newline
        requiredBufferSize += (25 * 24) + MAX_PATH + 25;
    }
    
    // Check if buffer is large enough
    if (BufferSize < requiredBufferSize) {
        ExFreePoolWithTag(featureVectors, REGISTRY_FEATURE_TAG);
        *ActualSize = requiredBufferSize; // Tell caller how much we need
        return STATUS_BUFFER_TOO_SMALL;
    }
    
    // Copy header
    RtlCopyMemory(CSVBuffer, csvHeader, strlen(csvHeader));
    currentOffset = (ULONG)strlen(csvHeader);
    
    // Write feature vectors
    for (ULONG i = 0; i < actualCount; i++) {
        PREGISTRY_FEATURE_VECTOR fv = &featureVectors[i];
        
        // Convert process name to ASCII
        CHAR processNameBuffer[MAX_PATH] = {0};
        ANSI_STRING ansiProcessName;
        UNICODE_STRING unicodeProcessName;
        
        // Initialize Unicode string from wide char array
        RtlInitUnicodeString(&unicodeProcessName, fv->ProcessName);
        
        // Convert to ANSI
        ansiProcessName.Buffer = processNameBuffer;
        ansiProcessName.Length = 0;
        ansiProcessName.MaximumLength = MAX_PATH;
        
        RtlUnicodeStringToAnsiString(&ansiProcessName, &unicodeProcessName, FALSE);
        
        // Format CSV row
        bytesWritten = 0;
        status = RtlStringCchPrintfA(
            (NTSTRSAFE_PSTR)(CSVBuffer + currentOffset),
            BufferSize - currentOffset,
            "%lu,%s,%llu,%llu,%llu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu\r\n",
            HandleToUlong(fv->ProcessId),
            ansiProcessName.Buffer,
            fv->FirstSeenTime,
            fv->LastSeenTime,
            fv->OperationDurationSec,
            fv->TotalOperationCount,
            fv->CreateOperationCount,
            fv->ModifyOperationCount,
            fv->DeleteOperationCount,
            fv->QueryOperationCount,
            fv->UniqueKeysAccessed,
            fv->AutorunKeysAccessed,
            fv->SecurityKeysAccessed,
            fv->FileAssocKeysAccessed,
            fv->NetworkingKeysAccessed,
            fv->ServicesKeysAccessed,
            fv->SensitiveKeysAccessed,
            fv->OperationBurstCount,
            fv->MaxOperationsPerBurst,
            fv->BurstIntervalMs,
            fv->RemoteOperationCount,
            fv->FileExtensionModificationCount,
            fv->SecuritySettingModificationCount
        );
        
        if (!NT_SUCCESS(status)) {
            ExFreePoolWithTag(featureVectors, REGISTRY_FEATURE_TAG);
            return status;
        }
        
        // Get length of formatted string
        size_t sizeTBytesWritten;
        status = RtlStringCchLengthA(
            (NTSTRSAFE_PSTR)(CSVBuffer + currentOffset),
            BufferSize - currentOffset,
            &sizeTBytesWritten
        );
        bytesWritten = (ULONG)sizeTBytesWritten;
        
        if (!NT_SUCCESS(status)) {
            ExFreePoolWithTag(featureVectors, REGISTRY_FEATURE_TAG);
            return status;
        }
        
        currentOffset += bytesWritten;
    }
    
    // Cleanup
    ExFreePoolWithTag(featureVectors, REGISTRY_FEATURE_TAG);
    
    // Return actual size
    *ActualSize = currentOffset;
    return STATUS_SUCCESS;
}

/**
    Reset all data in the registry analyzer.
*/
VOID 
RegistryAnalyzer::Reset()
{
    PPROCESS_REGISTRY_PROFILE currentProfile;
    
    // Acquire exclusive lock on profile list
    FltAcquirePushLockExclusive(&ProcessProfileLock);
    
    // Free all profiles in the list
    while (!IsListEmpty(&ProcessProfileListHead)) {
        currentProfile = CONTAINING_RECORD(RemoveHeadList(&ProcessProfileListHead), PROCESS_REGISTRY_PROFILE, ListEntry);
        FreeProcessProfile(currentProfile);
    }
    
    // Reset profile count
    ProfileCount = 0;
    
    // Release lock
    FltReleasePushLock(&ProcessProfileLock);
}
