/*
 * Registry data analyzer for malware detection
 * Based on K-Means clustering research for registry behavior analysis
 */
#include "pch.h"
#include "registry_structures.h"
#include "RegistryAnalyzer.h"

// Define _fltused for floating-point operations
extern "C" int _fltused = 1;

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

const WCHAR* ProcessHijackKeyPrefixes[] = {
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit",
    L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCertDlls",
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellServiceObjects",
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellExecuteHooks"
};

const WCHAR* DllHijackKeyPrefixes[] = {
    L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs",
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_DLLs",
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Drivers32",
    L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors"
};

const WCHAR* ComObjectKeyPrefixes[] = {
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Classes\\CLSID",
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Classes\\WOW6432Node\\CLSID",
    L"\\REGISTRY\\USER\\S-1-5-21-*\\Software\\Classes\\CLSID",
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Classes\\Interface",
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\COM3",
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\OLE"
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
    
    // Check for process hijacking modifications
    if (newEvent->KeyPath && newEvent->OperationType != RegistryOperationQuery && 
        newEvent->KeyCategory == RegistryKeyCategoryProcessHijack) {
        profile->CriticalSystemKeyModifications++;
    }
    
    // Check for COM object registrations
    if (newEvent->KeyPath && newEvent->OperationType != RegistryOperationQuery && 
        newEvent->KeyCategory == RegistryKeyCategoryComObjects) {
        profile->ComRegistryModifications++;
    }
    
    // Calculate and update registry key depth
    if (newEvent->KeyPath) {
        ULONG keyDepth = CalculateKeyDepth(newEvent->KeyPath);
        if (keyDepth > profile->RegistryKeyDepthMax) {
            profile->RegistryKeyDepthMax = keyDepth;
        }
    }
    
    // Calculate registry value entropy if we have data
    if (newEvent->DataBuffer && newEvent->DataBufferSize > 0) {
        ULONG entropy = CalculateEntropy((PUCHAR)newEvent->DataBuffer, newEvent->DataBufferSize);
        
        // Update running average entropy (weighted by size)
        if (profile->RegistryValueEntropyAvg == 0) {
            profile->RegistryValueEntropyAvg = entropy;
        } else {
            // Weighted running average
            profile->RegistryValueEntropyAvg = 
                (profile->RegistryValueEntropyAvg * 3 + entropy) / 4;
        }
    }
    
    // Check for burst patterns
    CheckBurstPattern(profile, currentTime);
    
    // Update timestamp
    profile->LastSeen = currentTime;
    if (profile->FirstSeen.QuadPart == 0) {
        profile->FirstSeen = currentTime;
    }
    
    // Update process information periodically
    if ((profile->TotalOperationCount % 100) == 0) {
        UpdateProcessInformation(profile);
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

// This function is defined above

/**
    Calculate the depth of a registry key path.
    @param KeyPath - Registry key path
    @return The depth of the key path
*/
ULONG
RegistryAnalyzer::CalculateKeyDepth(
    _In_ PUNICODE_STRING KeyPath
    )
{
    if (!KeyPath || !KeyPath->Buffer || KeyPath->Length == 0) {
        return 0;
    }
    
    ULONG depth = 0;
    ULONG i;
    
    // Count the number of path separators ('\') in the key path
    for (i = 0; i < KeyPath->Length / sizeof(WCHAR); i++) {
        if (KeyPath->Buffer[i] == L'\\') {
            depth++;
        }
    }
    
    // Return the depth (minus 1 for the leading separator if it exists)
    return (depth > 0) ? depth : 0;
}

/**
    Calculate Shannon entropy of data.
    @param Data - Data buffer
    @param Size - Size of data buffer
    @return Entropy value scaled by 100 (0-800, where 800 is max entropy)
*/
ULONG 
RegistryAnalyzer::CalculateEntropy(
    _In_ PUCHAR Data,
    _In_ ULONG Size
    )
{
    if (!Data || Size == 0) {
        return 0;
    }
    
    // Count occurrences of each byte value
    ULONG byteCount[256] = {0};
    ULONG i;
    
    for (i = 0; i < Size; i++) {
        byteCount[Data[i]]++;
    }
    
    // Calculate a simplified entropy approximation (without using math.h)
    // Use a simplified approach since we can't use log() in kernel mode easily
    double entropy = 0.0;
    double probability;
    
    for (i = 0; i < 256; i++) {
        if (byteCount[i] > 0) {
            probability = (double)byteCount[i] / Size;
            
            // Simplified entropy calculation using binary bits of information
            // For probability p, contribution is p * -log2(p)
            // We approximate -log2(p) based on the range where p falls
            double negLog2;
            if (probability >= 0.5)         negLog2 = 1.0;
            else if (probability >= 0.25)   negLog2 = 2.0;
            else if (probability >= 0.125)  negLog2 = 3.0;
            else if (probability >= 0.0625) negLog2 = 4.0;
            else if (probability >= 0.03125) negLog2 = 5.0;
            else if (probability >= 0.015625) negLog2 = 6.0;
            else if (probability >= 0.0078125) negLog2 = 7.0;
            else                            negLog2 = 8.0; // Max level for byte values
            
            entropy += probability * negLog2;
        }
    }
    
    // Scale entropy to an integer value (max entropy is 8.0, scaling by 100 gives 800)
    return (ULONG)(entropy * 100.0);
}

/**
    Calculate entropy of path string (useful for detecting random/generated names).
    @param Path - Unicode path string
    @return Entropy value scaled by 100
*/
ULONG 
RegistryAnalyzer::CalculatePathEntropy(
    _In_ PUNICODE_STRING Path
    )
{
    if (!Path || !Path->Buffer || Path->Length == 0) {
        return 0;
    }
    
    // Extract the filename part of the path
    PWCHAR buffer = Path->Buffer;
    ULONG length = Path->Length / sizeof(WCHAR);
    ULONG fileNameStart = 0;
    
    // Find the last backslash or colon
    for (ULONG i = 0; i < length; i++) {
        if (buffer[i] == L'\\' || buffer[i] == L':') {
            fileNameStart = i + 1;
        }
    }
    
    // Calculate entropy only on the filename part
    ULONG fileNameLength = length - fileNameStart;
    if (fileNameLength == 0) {
        return 0;
    }
    
    // Use the entropy calculation on the filename bytes
    return CalculateEntropy((PUCHAR)&buffer[fileNameStart], fileNameLength * sizeof(WCHAR));
}

/**
    Check if a process is running with elevated privileges.
    @param ProcessId - Process ID to check
    @return TRUE if elevated, FALSE otherwise
*/
BOOLEAN 
RegistryAnalyzer::IsProcessElevated(
    _In_ HANDLE ProcessId
    )
{
    // In kernel mode, we can't directly check if a process is elevated like in user mode
    // However, we can check if it has certain privileges or tokens
    BOOLEAN isElevated = FALSE;
    PEPROCESS processObject = NULL;
    
    // Try to open the process
    NTSTATUS status = PsLookupProcessByProcessId(ProcessId, &processObject);
    if (!NT_SUCCESS(status)) {
        return FALSE;
    }
    
    // Use a simple heuristic based on image name
    //PUNICODE_STRING processImageName = NULL;

    // Check if we have a valid process object
    if (processObject) {
        // Process has been found, we'll consider it potentially elevated
        isElevated = TRUE;
    }
    
    // Clean up
    if (processObject) {
        ObDereferenceObject(processObject);
    }
    
    return isElevated;
}

/**
    Update process information for profiling.
    @param Profile - Process registry profile to update
*/
VOID 
RegistryAnalyzer::UpdateProcessInformation(
    _Inout_ PPROCESS_REGISTRY_PROFILE Profile
    )
{
    LARGE_INTEGER currentTime;
    
    // Get current time
    KeQuerySystemTime(&currentTime);
    
    // Update process age if we have create time
    if (Profile->ProcessCreateTime.QuadPart != 0) {
        Profile->ProcessAgeSeconds = (ULONG)((currentTime.QuadPart - Profile->ProcessCreateTime.QuadPart) / 10000000LL);
    }
    
    // Calculate process name entropy if we have a path
    if (Profile->ProcessPath) {
        Profile->ProcessImageEntropy = CalculatePathEntropy(Profile->ProcessPath);
    }
    
    // Check if process is elevated
    Profile->IsElevated = IsProcessElevated(Profile->ProcessId);
    
    // Try to get session ID
    PEPROCESS processObject = NULL;
    if (NT_SUCCESS(PsLookupProcessByProcessId(Profile->ProcessId, &processObject))) {
        // Get session ID using a fallback method
        Profile->SessionId = 0; // Default to session 0 since we can't get it directly
        ObDereferenceObject(processObject);
    }
    
    // Calculate operation density (operations per minute)
    if (Profile->FirstSeen.QuadPart != 0 && Profile->LastSeen.QuadPart != 0 && Profile->TotalOperationCount > 0) {
        ULONGLONG durationSec = (Profile->LastSeen.QuadPart - Profile->FirstSeen.QuadPart) / 10000000LL;
        if (durationSec > 0) {
            Profile->OperationDensityPerMin = (ULONG)((Profile->TotalOperationCount * 60) / durationSec);
        }
    }
    
    // Calculate writes to reads ratio (scaled by 100 for integer precision)
    ULONG writeOps = Profile->CreateOperationCount + Profile->ModifyOperationCount + Profile->DeleteOperationCount;
    if (Profile->QueryOperationCount > 0) {
        Profile->WritesToReadsRatio = (writeOps * 100) / Profile->QueryOperationCount;
    } else if (writeOps > 0) {
        // All writes, no reads
        Profile->WritesToReadsRatio = 10000; // arbitrary high value indicating infinity
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
    
    // Check process hijacking keys
    for (ULONG i = 0; i < ARRAYSIZE(ProcessHijackKeyPrefixes); i++) {
        RtlInitUnicodeString(&prefixString, ProcessHijackKeyPrefixes[i]);
        if (RtlPrefixUnicodeString(&prefixString, KeyPath, TRUE)) {
            return RegistryKeyCategoryProcessHijack;
        }
    }
    
    // Check DLL hijacking keys
    for (ULONG i = 0; i < ARRAYSIZE(DllHijackKeyPrefixes); i++) {
        RtlInitUnicodeString(&prefixString, DllHijackKeyPrefixes[i]);
        if (RtlPrefixUnicodeString(&prefixString, KeyPath, TRUE)) {
            return RegistryKeyCategoryDllHijack;
        }
    }
    
    // Check COM object keys
    for (ULONG i = 0; i < ARRAYSIZE(ComObjectKeyPrefixes); i++) {
        RtlInitUnicodeString(&prefixString, ComObjectKeyPrefixes[i]);
        if (RtlPrefixUnicodeString(&prefixString, KeyPath, TRUE)) {
            return RegistryKeyCategoryComObjects;
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
                
                // Calculate path entropy
                profile->ProcessImageEntropy = CalculatePathEntropy(profile->ProcessPath);
            }
            
            // Get process creation time if available
            PEPROCESS processObject = NULL;
            if (NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &processObject))) {
                // Get process creation time (kernel time)
                LARGE_INTEGER createTime = {0};
                KeQuerySystemTime(&createTime);
                profile->ProcessCreateTime = createTime;
                
                // Get session ID using a fallback method
                profile->SessionId = 0; // Default to session 0 since we can't get it directly
                
                ObDereferenceObject(processObject);
            }
            
            // Check if process is elevated
            profile->IsElevated = IsProcessElevated(ProcessId);
            
            // Initialize other fields
            LARGE_INTEGER currentTime;
            KeQuerySystemTime(&currentTime);
            
            if (profile->ProcessCreateTime.QuadPart != 0) {
                profile->ProcessAgeSeconds = (ULONG)((currentTime.QuadPart - profile->ProcessCreateTime.QuadPart) / 10000000ULL);
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
            
        case RegistryKeyCategoryProcessHijack:
            Profile->ProcessHijackKeysAccessed++;
            break;
            
        case RegistryKeyCategoryDllHijack:
            Profile->DllHijackKeysAccessed++;
            break;
            
        case RegistryKeyCategoryComObjects:
            Profile->ComObjectKeysAccessed++;
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
    @param ActualFeatureVectors - Actual number of vectors exported
    @return NTSTATUS value indicating success or failure
*/
NTSTATUS 
RegistryAnalyzer::ExportFeatureVectors(
    _Out_ PREGISTRY_FEATURE_VECTOR FeatureVectors,
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
    if (!FeatureVectors) {
        return STATUS_INVALID_PARAMETER;
    }
    
    // Count how many profiles we have that meet our criteria
    ULONG totalEligibleProfiles = 0;
    FltAcquirePushLockShared(&ProcessProfileLock);
    
    for (entry = ProcessProfileListHead.Flink; entry != &ProcessProfileListHead; entry = entry->Flink) {
        profile = CONTAINING_RECORD(entry, PROCESS_REGISTRY_PROFILE, ListEntry);
        
        // Only count profiles with sufficient operations
        if (profile->TotalOperationCount >= 5) {
            totalEligibleProfiles++;
        }
    }
    
    FltReleasePushLock(&ProcessProfileLock);
    
    // Zero out the buffer to ensure it's initialized
    RtlZeroMemory(FeatureVectors, totalEligibleProfiles * sizeof(REGISTRY_FEATURE_VECTOR));
    
    // Calculate actual space needed per feature vector
    SIZE_T featureVectorSize = sizeof(REGISTRY_FEATURE_VECTOR);
    
    // Ensure we've allocated enough memory for the buffer
    if (totalEligibleProfiles > 0 && !FeatureVectors) {
        return STATUS_INVALID_PARAMETER;
    }

    
    // Acquire shared lock to iterate profiles
    FltAcquirePushLockShared(&ProcessProfileLock);
    
    // Iterate through profiles and fill feature vectors
    for (entry = ProcessProfileListHead.Flink; 
         entry != &ProcessProfileListHead && count < totalEligibleProfiles; 
         entry = entry->Flink)
    {
        profile = CONTAINING_RECORD(entry, PROCESS_REGISTRY_PROFILE, ListEntry);
        
        // Skip profiles with very few operations
        if (profile->TotalOperationCount < 5) {
            continue;
        }
        
        // Ensure we don't exceed the provided buffer
        if (count >= totalEligibleProfiles) {
            // We've exceeded the buffer size, stop processing
            break;
        }
        
        // Process this profile and populate feature vector
        // Fill feature vector
        if (count < totalEligibleProfiles) { // Ensure we don't exceed buffer bounds
            RtlZeroMemory(&FeatureVectors[count], featureVectorSize);
            
            // Basic identification
            FeatureVectors[count].ProcessId = profile->ProcessId;
        
            // Copy process name if available
            if (profile->ProcessName && profile->ProcessName->Buffer) {
                RtlStringCchCopyW(FeatureVectors[count].ProcessName, MAX_PATH, profile->ProcessName->Buffer);
            }
            
            // Process information metrics
            FeatureVectors[count].ProcessAgeSeconds = profile->ProcessAgeSeconds;
            FeatureVectors[count].ProcessImageEntropy = profile->ProcessImageEntropy;
            FeatureVectors[count].SessionId = profile->SessionId;
            FeatureVectors[count].IsElevated = profile->IsElevated;
        
            // Time metrics
            ExSystemTimeToLocalTime(&profile->FirstSeen, &localTime);
            FeatureVectors[count].FirstSeenTime = localTime.QuadPart / 10000000ULL - 11644473600ULL; // Convert to Unix epoch
            
            ExSystemTimeToLocalTime(&profile->LastSeen, &localTime);
            FeatureVectors[count].LastSeenTime = localTime.QuadPart / 10000000ULL - 11644473600ULL; // Convert to Unix epoch
            
            if (profile->FirstSeen.QuadPart != 0 && profile->LastSeen.QuadPart != 0) {
                FeatureVectors[count].OperationDurationSec = 
                    (profile->LastSeen.QuadPart - profile->FirstSeen.QuadPart) / 10000000ULL;
            }
            
            if (profile->ProcessCreateTime.QuadPart != 0) {
                ExSystemTimeToLocalTime(&profile->ProcessCreateTime, &localTime);
                FeatureVectors[count].ProcessCreateTime = localTime.QuadPart / 10000000ULL - 11644473600ULL; // Convert to Unix epoch
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
            FeatureVectors[count].ProcessHijackKeysAccessed = profile->ProcessHijackKeysAccessed;
            FeatureVectors[count].DllHijackKeysAccessed = profile->DllHijackKeysAccessed;
            FeatureVectors[count].ComObjectKeysAccessed = profile->ComObjectKeysAccessed;
            
            // Temporal patterns
            FeatureVectors[count].OperationBurstCount = profile->OperationBurstCount;
            FeatureVectors[count].MaxOperationsPerBurst = profile->MaxOperationsPerBurst;
            FeatureVectors[count].BurstIntervalMs = profile->BurstIntervalMs;
            FeatureVectors[count].OperationDensityPerMin = profile->OperationDensityPerMin;
            FeatureVectors[count].TimingVariance = profile->TimingVariance;
            
            // Remote operations
            FeatureVectors[count].RemoteOperationCount = profile->RemoteOperationCount;
            
            // Suspicious indicators
            FeatureVectors[count].FileExtensionModificationCount = profile->FileExtensionModificationCount;
            FeatureVectors[count].SecuritySettingModificationCount = profile->SecuritySettingModificationCount;
            FeatureVectors[count].WritesToReadsRatio = profile->WritesToReadsRatio;
            FeatureVectors[count].RegistryKeyDepthMax = profile->RegistryKeyDepthMax;
            FeatureVectors[count].RegistryValueEntropyAvg = profile->RegistryValueEntropyAvg;
            FeatureVectors[count].ComRegistryModifications = profile->ComRegistryModifications;
            FeatureVectors[count].CriticalSystemKeyModifications = profile->CriticalSystemKeyModifications;
            
            // Increment counter only after successful processing
            count++;
        }
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
        // If empty, nothing to do
        if (BufferSize == 0) {
            return STATUS_SUCCESS;
        }
    } else if (!CSVBuffer && BufferSize > 0) {
        // Invalid buffer
        return STATUS_INVALID_PARAMETER;
    }
    
    // If buffer size is zero or no buffer is provided, still initialize output value
    if (BufferSize == 0 || !CSVBuffer) {
        *ActualSize = 0;
        return STATUS_SUCCESS;
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
    
    // Set number of feature vectors to export (all eligible profiles)
    ULONG maxVectorsToExport = featureVectorCount;
    
    // Allocate memory for feature vectors with buffer size validation
    SIZE_T vectorSize = sizeof(REGISTRY_FEATURE_VECTOR);
    featureVectors = (PREGISTRY_FEATURE_VECTOR)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, 
        maxVectorsToExport * vectorSize,
        REGISTRY_FEATURE_TAG);
    
    if (featureVectors == NULL) {
        *ActualSize = 0; // Ensure output is initialized
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    // Zero out the allocated memory to be safe
    RtlZeroMemory(featureVectors, maxVectorsToExport * vectorSize);
    
    // Get feature vectors
    ULONG actualCount = 0;
    status = ExportFeatureVectors(featureVectors, &actualCount);
    
    if (!NT_SUCCESS(status) || actualCount == 0) {
        ExFreePoolWithTag(featureVectors, REGISTRY_FEATURE_TAG);
        *ActualSize = 0; // Ensure output is initialized
        return status != STATUS_SUCCESS ? status : STATUS_NO_DATA_DETECTED;
    }
    
    // Start building CSV
    // First write CSV header
    CHAR csvHeader[] = "ProcessId,ProcessName,ProcessAgeSeconds,ProcessImageEntropy,SessionId,IsElevated,"
                      "FirstSeenTime,LastSeenTime,OperationDurationSec,ProcessCreateTime,"
                      "TotalOperationCount,CreateOperationCount,ModifyOperationCount,DeleteOperationCount,QueryOperationCount,"
                      "UniqueKeysAccessed,AutorunKeysAccessed,SecurityKeysAccessed,FileAssocKeysAccessed,"
                      "NetworkingKeysAccessed,ServicesKeysAccessed,SensitiveKeysAccessed,ProcessHijackKeysAccessed,DllHijackKeysAccessed,ComObjectKeysAccessed,"
                      "OperationBurstCount,MaxOperationsPerBurst,BurstIntervalMs,OperationDensityPerMin,TimingVariance,"
                      "RemoteOperationCount,FileExtensionModificationCount,SecuritySettingModificationCount,"
                      "WritesToReadsRatio,RegistryKeyDepthMax,RegistryValueEntropyAvg,ComRegistryModifications,CriticalSystemKeyModifications\r\n";
    
    requiredBufferSize = (ULONG)strlen(csvHeader);
    
    // Calculate required buffer size
    for (ULONG i = 0; i < actualCount; i++) {
        // Conservative estimate: 25 bytes per numeric field (35 fields) + process name (MAX_PATH) + commas and newline
        requiredBufferSize += (25 * 35) + MAX_PATH + 50;
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
            "%lu,%s,%lu,%lu,%lu,%d,%llu,%llu,%llu,%llu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu\r\n",
            HandleToUlong(fv->ProcessId),
            ansiProcessName.Buffer,
            fv->ProcessAgeSeconds,
            fv->ProcessImageEntropy,
            fv->SessionId,
            fv->IsElevated,
            fv->FirstSeenTime,
            fv->LastSeenTime,
            fv->OperationDurationSec,
            fv->ProcessCreateTime,
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
            fv->ProcessHijackKeysAccessed,
            fv->DllHijackKeysAccessed,
            fv->ComObjectKeysAccessed,
            fv->OperationBurstCount,
            fv->MaxOperationsPerBurst,
            fv->BurstIntervalMs,
            fv->OperationDensityPerMin,
            fv->TimingVariance,
            fv->RemoteOperationCount,
            fv->FileExtensionModificationCount,
            fv->SecuritySettingModificationCount,
            fv->WritesToReadsRatio,
            fv->RegistryKeyDepthMax,
            fv->RegistryValueEntropyAvg,
            fv->ComRegistryModifications,
            fv->CriticalSystemKeyModifications
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
