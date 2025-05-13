#include "Commands.h"
#include "IOCTLShared.h"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <string>
#include <vector>
#include <locale>
#include <codecvt>
#include <Windows.h>

// Convert LARGE_INTEGER time to readable format
// Convert LARGE_INTEGER time to readable format
std::wstring FormatTime(const LARGE_INTEGER &time)
{
    // If time is zero or very small (invalid), return placeholder
    if (time.QuadPart == 0 || time.QuadPart < 10000000) // Less than 1 second
    {
        return L"N/A";
    }

    SYSTEMTIME systemTime;
    FILETIME fileTime;
    fileTime.dwLowDateTime = time.LowPart;
    fileTime.dwHighDateTime = time.HighPart;

    // Convert to local time
    FILETIME localFileTime;
    if (FileTimeToLocalFileTime(&fileTime, &localFileTime))
    {
        fileTime = localFileTime;
    }

    if (!FileTimeToSystemTime(&fileTime, &systemTime))
    {
        return L"Invalid Time";
    }

    wchar_t buffer[100];
    swprintf_s(buffer, L"%04d-%02d-%02d %02d:%02d:%02d",
               systemTime.wYear, systemTime.wMonth, systemTime.wDay,
               systemTime.wHour, systemTime.wMinute, systemTime.wSecond);

    return std::wstring(buffer);
}

// Convert std::string to std::wstring
std::wstring StringToWString(const std::string &str)
{
    if (str.empty())
        return std::wstring();

    int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
    std::wstring wstr(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstr[0], size_needed);
    return wstr;
}

// Convert std::wstring to std::string
std::string WStringToString(const std::wstring &wstr)
{
    if (wstr.empty())
        return std::string();

    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string str(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &str[0], size_needed, NULL, NULL);
    return str;
}

// Function to get error message from Windows error code
std::string GetLastErrorAsString()
{
    DWORD errorCode = GetLastError();
    if (errorCode == 0)
    {
        return std::string();
    }

    LPSTR messageBuffer = nullptr;
    size_t size = FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, errorCode, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);

    std::string message(messageBuffer, size);
    LocalFree(messageBuffer);

    return message;
}

// Open handle to the driver device
HANDLE OpenDriverHandle()
{
    HANDLE hDevice = CreateFile(
        DEVICE_NAME,                        // Device name
        GENERIC_READ | GENERIC_WRITE,       // Desired access
        FILE_SHARE_READ | FILE_SHARE_WRITE, // Share mode
        NULL,                               // Security attributes
        OPEN_EXISTING,                      // Creation disposition
        FILE_ATTRIBUTE_NORMAL,              // Flags and attributes
        NULL                                // Template file
    );

    if (hDevice == INVALID_HANDLE_VALUE)
    {
        std::cerr << "Failed to open device: " << GetLastErrorAsString() << std::endl;
        std::cerr << "Make sure the driver is installed and running." << std::endl;
    }

    return hDevice;
}

// Close driver handle
void CloseDriverHandle(HANDLE hDevice)
{
    if (hDevice != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hDevice);
    }
}

// Command: process-list
void CommandProcessList()
{
    HANDLE hDevice = OpenDriverHandle();
    if (hDevice == INVALID_HANDLE_VALUE)
    {
        return;
    }

    // First get just the count in a small buffer
    DWORD bytesReturned = 0;
    DWORD initialBufferSize = sizeof(PROCESS_LIST); // Just enough for Count
    BYTE *countBuffer = new BYTE[initialBufferSize];
    BOOL success = DeviceIoControl(
        hDevice,
        IOCTL_GET_PROCESS_LIST,
        NULL, 0,
        countBuffer, initialBufferSize,
        &bytesReturned,
        NULL);

    PPROCESS_LIST pInitialList = reinterpret_cast<PPROCESS_LIST>(countBuffer);
    ULONG processCount = 0;
    
    if (success || GetLastError() == ERROR_INSUFFICIENT_BUFFER)
    {
        // Extract the count of processes
        processCount = pInitialList->Count;
        std::cout << "Total processes found: " << processCount << std::endl;
    }
    else
    {
        std::cerr << "Failed to get process count: " << GetLastErrorAsString() << std::endl;
        delete[] countBuffer;
        CloseDriverHandle(hDevice);
        return;
    }
    delete[] countBuffer;
    
    // Now allocate enough space for all the processes
    // Make sure to use at least 50 as a minimum even if count is less
    ULONG allocCount = max(50, processCount + 10); // Add some extra space just in case
    DWORD fullBufferSize = sizeof(PROCESS_LIST) + (allocCount - 1) * sizeof(PROCESS_INFO);
    
    std::cout << "Allocating buffer for " << allocCount << " processes (" << fullBufferSize << " bytes)" << std::endl;
    
    BYTE *fullBuffer = new BYTE[fullBufferSize];
    success = DeviceIoControl(
        hDevice,
        IOCTL_GET_PROCESS_LIST,
        NULL, 0,
        fullBuffer, fullBufferSize,
        &bytesReturned,
        NULL);

    if (success)
    {
        PPROCESS_LIST pList = reinterpret_cast<PPROCESS_LIST>(fullBuffer);

        // Print header
        std::cout << std::left << std::setw(8) << "PID"
                  << std::setw(8) << "PPID"
                  << std::setw(30) << "Image Name"
                  << "Creation Time" << std::endl;
        std::cout << std::string(80, '-') << std::endl;

        // Print each process
        for (ULONG i = 0; i < pList->Count; i++)
        {
            PROCESS_INFO &proc = pList->Processes[i];

            // Extract filename from full path
            std::wstring fullPath = proc.ImagePath;
            size_t lastSlash = fullPath.find_last_of(L"\\");
            std::wstring fileName = (lastSlash != std::wstring::npos) ? fullPath.substr(lastSlash + 1) : fullPath;

            std::cout << std::left
                      << std::setw(8) << proc.ProcessId
                      << std::setw(8) << proc.ParentProcessId
                      << std::setw(30) << WStringToString(fileName)
                      << WStringToString(FormatTime(proc.CreationTime))
                      << (proc.IsTerminated ? " [Terminated]" : "")
                      << std::endl;
        }

        std::cout << std::endl
                  << "Total processes returned: " << pList->Count << std::endl;
    }
    else
    {
        std::cerr << "Failed to get process list: " << GetLastErrorAsString() << std::endl;
    }

    delete[] fullBuffer;
    CloseDriverHandle(hDevice);
}

// Command: process-info
// Command: process-info
void CommandProcessInfo(ULONG ProcessId)
{
    HANDLE hDevice = OpenDriverHandle();
    if (hDevice == INVALID_HANDLE_VALUE)
    {
        return;
    }

    // Set up the request
    PROCESS_DETAILS_REQUEST request;
    request.ProcessId = ProcessId;

    // Buffer for the result
    const DWORD bufferSize = 4096;
    BYTE buffer[bufferSize] = {0};
    DWORD bytesReturned = 0;

    BOOL success = DeviceIoControl(
        hDevice,
        IOCTL_GET_PROCESS_DETAILS,
        &request, sizeof(request),
        buffer, bufferSize,
        &bytesReturned,
        NULL);

    if (success)
    {
        // Assuming we got back a PROCESS_INFO structure
        PPROCESS_INFO pInfo = reinterpret_cast<PPROCESS_INFO>(buffer);

        // Print detailed information
        std::cout << "Process Details" << std::endl;
        std::cout << "==============" << std::endl;
        std::cout << "Process ID:             " << pInfo->ProcessId << std::endl;
        std::cout << "Parent ID:              " << pInfo->ParentProcessId << std::endl;
        std::cout << "Image Path:             " << WStringToString(pInfo->ImagePath) << std::endl;
        std::cout << "Command Line:           " << WStringToString(pInfo->CommandLine) << std::endl;
        std::cout << "Creation Time:          " << WStringToString(FormatTime(pInfo->CreationTime)) << std::endl;
        std::cout << "Status:                 " << (pInfo->IsTerminated ? "Terminated" : "Running") << std::endl;
        
        // Malware detection information
        std::cout << std::endl;
        std::cout << "Security Analysis" << std::endl;
        std::cout << "================" << std::endl;
        std::cout << "Anomaly Score:          " << pInfo->AnomalyScore << "/100" << 
            (pInfo->AnomalyScore > 70 ? " [HIGH RISK]" : 
             pInfo->AnomalyScore > 40 ? " [SUSPICIOUS]" : 
             pInfo->AnomalyScore > 20 ? " [LOW RISK]" : " [NORMAL]") << std::endl;
        
        std::cout << "Loaded Modules:         " << pInfo->LoadedModuleCount << std::endl;
        std::cout << "Thread Count:           " << pInfo->ThreadCount << std::endl;
        
        if (pInfo->HasRemoteLoadedModules)
        {
            std::cout << "Remote Loaded Modules:   " << pInfo->RemoteLoadCount << " [SUSPICIOUS]" << std::endl;
            std::cout << "First Remote Module:     " << WStringToString(pInfo->FirstRemoteModule) << std::endl;
        }
        else
        {
            std::cout << "Remote Loaded Modules:   None" << std::endl;
        }
        
        if (pInfo->HasRemoteCreatedThreads)
        {
            std::cout << "Remote Created Threads:  " << pInfo->RemoteThreadCount << " [SUSPICIOUS]" << std::endl;
            std::cout << "First Thread Creator:    PID " << pInfo->FirstRemoteThreadCreator << std::endl;
            std::cout << "First Thread Address:    0x" << std::hex << pInfo->FirstRemoteThreadAddress << std::dec << std::endl;
        }
        else
        {
            std::cout << "Remote Created Threads:  None" << std::endl;
        }
        
        // Security recommendations
        if (pInfo->AnomalyScore > 40)
        {
            std::cout << std::endl;
            std::cout << "Security Recommendations:" << std::endl;
            std::cout << "-------------------------" << std::endl;
            
            if (pInfo->HasRemoteLoadedModules)
            {
                std::cout << "* Suspicious remote DLL injection detected!" << std::endl;
                std::cout << "  This is a common technique used by malware and hackers." << std::endl;
            }
            
            if (pInfo->HasRemoteCreatedThreads)
            {
                std::cout << "* Suspicious remote thread creation detected!" << std::endl;
                std::cout << "  This could indicate code injection or unauthorized access." << std::endl;
            }
            
            // Add more specific recommendations based on other factors
            std::cout << "* Consider investigating this process further or terminating it if suspicious." << std::endl;
        }
    }
    else
    {
        std::cerr << "Failed to get process details: " << GetLastErrorAsString() << std::endl;
    }

    CloseDriverHandle(hDevice);
}

// Command: registry-monitor
void CommandRegistryMonitor(ULONG Count)
{
    HANDLE hDevice = OpenDriverHandle();
    if (hDevice == INVALID_HANDLE_VALUE)
    {
        return;
    }

    // Allocate a buffer for the results
    DWORD initialProcessCount = 100; // Expect up to 100 processes initially
    DWORD bufferSize = sizeof(PROCESS_LIST) + (initialProcessCount - 1) * sizeof(PROCESS_INFO);
    BYTE *buffer = new BYTE[bufferSize];
    DWORD bytesReturned = 0;

    BOOL success = DeviceIoControl(
        hDevice,
        IOCTL_GET_REGISTRY_ACTIVITY,
        &Count, sizeof(Count), // Pass count as input
        buffer, bufferSize,
        &bytesReturned,
        NULL);

    if (success)
    {
        PREGISTRY_ACTIVITY_LIST pList = reinterpret_cast<PREGISTRY_ACTIVITY_LIST>(buffer);

        // Print header
        std::cout << std::left << std::setw(8) << "PID"
                  << std::setw(20) << "Process"
                  << std::setw(10) << "Operation"
                  << std::setw(20) << "Timestamp"
                  << "Registry Path" << std::endl;
        std::cout << std::string(100, '-') << std::endl;

        // Print each registry activity
        for (ULONG i = 0; i < pList->Count; i++)
        {
            REGISTRY_ACTIVITY &activity = pList->Activities[i];

            // Map operation type to string
            std::string opType;
            switch (activity.OperationType)
            {
            case 0:
                opType = "Read";
                break;
            case 1:
                opType = "Write";
                break;
            case 2:
                opType = "Delete";
                break;
            case 3:
                opType = "Create";
                break;
            default:
                opType = "Unknown";
                break;
            }

            // Extract process name from full path
            std::wstring procPath = activity.ProcessName;
            size_t lastSlash = procPath.find_last_of(L"\\");
            std::wstring procName = (lastSlash != std::wstring::npos) ? procPath.substr(lastSlash + 1) : procPath;

            std::cout << std::left
                      << std::setw(8) << activity.ProcessId
                      << std::setw(20) << WStringToString(procName)
                      << std::setw(10) << opType
                      << std::setw(20) << WStringToString(FormatTime(activity.Timestamp))
                      << WStringToString(activity.RegistryPath) << std::endl;
        }

        std::cout << std::endl
                  << "Total registry operations: " << pList->Count << std::endl;
    }
    else
    {
        std::cerr << "Failed to get registry activity: " << GetLastErrorAsString() << std::endl;
    }

    delete[] buffer;
    CloseDriverHandle(hDevice);
}

// Command: add-registry-filter
void CommandAddRegistryFilter(const std::wstring &RegistryPath, ULONG FilterFlags)
{
    HANDLE hDevice = OpenDriverHandle();
    if (hDevice == INVALID_HANDLE_VALUE)
    {
        return;
    }

    // Prepare input data
    REGISTRY_FILTER filter;
    memset(&filter, 0, sizeof(filter));

    // Copy the registry path
    wcsncpy_s(filter.RegistryPath, RegistryPath.c_str(), _TRUNCATE);
    filter.FilterFlags = FilterFlags;

    DWORD bytesReturned = 0;
    BOOL success = DeviceIoControl(
        hDevice,
        IOCTL_ADD_REGISTRY_FILTER,
        &filter, sizeof(filter),
        NULL, 0, // No output data needed
        &bytesReturned,
        NULL);

    if (success)
    {
        std::cout << "Registry filter added successfully for path: " << WStringToString(RegistryPath) << std::endl;

        // Display the filter flags
        std::cout << "Protection flags: ";
        if (FilterFlags & 0x1)
            std::cout << "Read ";
        if (FilterFlags & 0x2)
            std::cout << "Write ";
        if (FilterFlags & 0x4)
            std::cout << "Delete ";
        std::cout << std::endl;
    }
    else
    {
        std::cerr << "Failed to add registry filter: " << GetLastErrorAsString() << std::endl;
    }

    CloseDriverHandle(hDevice);
}

// Command: dll-monitor
void CommandDllMonitor(ULONG ProcessId)
{
    HANDLE hDevice = OpenDriverHandle();
    if (hDevice == INVALID_HANDLE_VALUE)
    {
        return;
    }

    // Allocate a sufficiently large buffer for numerous DLLs
    DWORD bufferSize = sizeof(IMAGE_LOAD_LIST) + 999 * sizeof(IMAGE_LOAD_INFO); // Space for 1000 DLLs
    BYTE *buffer = nullptr;
    DWORD bytesReturned = 0;
    BOOL success = false;

    std::cout << "Searching for loaded modules";
    if (ProcessId != 0) {
        std::cout << " in process " << ProcessId;
    }
    std::cout << "..." << std::endl;

    // Allocate buffer and make the IOCTL call
    buffer = new BYTE[bufferSize];
    success = DeviceIoControl(
        hDevice,
        IOCTL_GET_IMAGE_LOAD_HISTORY,
        &ProcessId, sizeof(ProcessId),
        buffer, bufferSize,
        &bytesReturned,
        NULL);

    if (success)
    {
        PIMAGE_LOAD_LIST pList = reinterpret_cast<PIMAGE_LOAD_LIST>(buffer);

        if (pList->Count == 0)
        {
            std::cout << "No loaded modules found." << std::endl;
        }
        else
        {
            // Print header
            std::cout << std::left << std::setw(8) << "PID"
                    << std::setw(16) << "Base Address"
                    << std::setw(10) << "Size"
                    << std::setw(7) << "Remote"
                    << std::setw(8) << "Risk"
                    << "Image Path / Flags" << std::endl;
            std::cout << std::string(120, '-') << std::endl;

            // Count risk levels
            int highRiskCount = 0;
            int mediumRiskCount = 0;
            int lowRiskCount = 0;

            // Print each image load
            for (ULONG i = 0; i < pList->Count; i++)
            {
                IMAGE_LOAD_INFO &img = pList->LoadedImages[i];

                // Get risk level string
                std::string riskStr;
                switch(img.RiskLevel) {
                    case 3: 
                        riskStr = "HIGH";
                        highRiskCount++;
                        break;
                    case 2: 
                        riskStr = "MEDIUM";
                        mediumRiskCount++;
                        break;
                    case 1: 
                        riskStr = "LOW";
                        lowRiskCount++;
                        break;
                    default: 
                        riskStr = "NONE";
                        break;
                }

                // Print the base info
                std::cout << std::left
                        << std::setw(8) << img.ProcessId
                        << std::setw(16) << "0x" << std::hex << img.ImageBase << std::dec
                        << std::setw(10) << (img.ImageSize / 1024) << "K"
                        << std::setw(7) << (img.RemoteLoad ? "Yes" : "No")
                        << std::setw(8) << riskStr
                        << WStringToString(img.ImagePath);

                // Print flags if present
                if (img.Flags != 0) {
                    std::cout << std::endl << std::string(49, ' ') << "Flags: ";
                    
                    if (img.Flags & IMAGE_FLAG_REMOTE_LOADED)
                        std::cout << "[Remote] ";
                    if (img.Flags & IMAGE_FLAG_NON_SYSTEM)
                        std::cout << "[Non-System] ";
                    if (img.Flags & IMAGE_FLAG_SUSPICIOUS_LOCATION)
                        std::cout << "[Suspicious Location] ";
                    if (img.Flags & IMAGE_FLAG_POTENTIAL_HIJACK)
                        std::cout << "[POTENTIAL HIJACK] ";
                    if (img.Flags & IMAGE_FLAG_NETWORK_RELATED)
                        std::cout << "[Network] ";
                    if (img.Flags & IMAGE_FLAG_HOOK_RELATED)
                        std::cout << "[Hook Related] ";
                    if (img.Flags & IMAGE_FLAG_UNSIGNED)
                        std::cout << "[Unsigned] ";
                }

                // If it's a remote load, show the process that loaded it
                if (img.RemoteLoad)
                {
                    std::cout << std::endl << std::string(49, ' ') 
                              << "Loaded by PID: " << img.CallerProcessId;
                }
                
                std::cout << std::endl;
                
                // Add separator for high risk items
                if (img.RiskLevel == 3) {
                    std::cout << std::string(120, '=') << std::endl;
                }
            }

            std::cout << std::endl
                    << "Total loaded modules: " << pList->Count
                    << (ProcessId ? std::string(" for process ") + std::to_string(ProcessId) : "")
                    << std::endl;
                    
            // Print risk summary
            if (highRiskCount > 0 || mediumRiskCount > 0) {
                std::cout << std::endl << "Risk Summary:" << std::endl;
                std::cout << "--------------" << std::endl;
                
                if (highRiskCount > 0) {
                    std::cout << "HIGH RISK modules: " << highRiskCount << std::endl;
                }
                
                if (mediumRiskCount > 0) {
                    std::cout << "MEDIUM RISK modules: " << mediumRiskCount << std::endl;
                }
                
                if (lowRiskCount > 0) {
                    std::cout << "LOW RISK modules: " << lowRiskCount << std::endl;
                }
                
                // Print security recommendations for high risk items
                if (highRiskCount > 0) {
                    std::cout << std::endl << "SECURITY RECOMMENDATIONS:" << std::endl;
                    std::cout << "-------------------------" << std::endl;
                    
                    if (highRiskCount > 0) {
                        std::cout << "* Investigate HIGH RISK modules as they may indicate code injection or DLL hijacking" << std::endl;
                    }
                    
                    if (mediumRiskCount > 0) {
                        std::cout << "* Review MEDIUM RISK modules for potentially suspicious behavior" << std::endl;
                    }
                }
            }
        }
    }
    else
    {
        std::cerr << "Failed to get image load history: " << GetLastErrorAsString() << std::endl;
    }

    delete[] buffer;
    CloseDriverHandle(hDevice);
}

// Command: thread-monitor
// Command: thread-monitor
void CommandThreadMonitor(ULONG ProcessId)
{
    HANDLE hDevice = OpenDriverHandle();
    if (hDevice == INVALID_HANDLE_VALUE)
    {
        return;
    }

    // Allocate a sufficiently large buffer for numerous threads
    DWORD bufferSize = sizeof(THREAD_LIST) + 999 * sizeof(THREAD_INFO); // Space for 1000 threads
    BYTE *buffer = nullptr;
    DWORD bytesReturned = 0;
    BOOL success = false;

    std::cout << "Searching for thread creation history";
    if (ProcessId != 0) {
        std::cout << " in process " << ProcessId;
    }
    std::cout << "..." << std::endl;

    // Allocate buffer and make the IOCTL call
    buffer = new BYTE[bufferSize];
    success = DeviceIoControl(
        hDevice,
        IOCTL_GET_THREAD_CREATION_HISTORY,
        &ProcessId, sizeof(ProcessId),
        buffer, bufferSize,
        &bytesReturned,
        NULL);

    if (success)
    {
        PTHREAD_LIST pList = reinterpret_cast<PTHREAD_LIST>(buffer);

        if (pList->Count == 0)
        {
            std::cout << "No thread history found." << std::endl;
        }
        else
        {
            // Print header
            std::cout << std::left << std::setw(8) << "TID"
                    << std::setw(8) << "PID"
                    << std::setw(18) << "Start Address"
                    << std::setw(8) << "Creator"
                    << std::setw(7) << "Remote"
                    << std::setw(8) << "Risk"
                    << "Creation Time / Flags" << std::endl;
            std::cout << std::string(120, '-') << std::endl;

            // Count risk levels
            int highRiskCount = 0;
            int mediumRiskCount = 0;
            int lowRiskCount = 0;

            // Print each thread
            for (ULONG i = 0; i < pList->Count; i++)
            {
                THREAD_INFO &thread = pList->Threads[i];

                // Get risk level string
                std::string riskStr;
                switch(thread.RiskLevel) {
                    case 3: 
                        riskStr = "HIGH";
                        highRiskCount++;
                        break;
                    case 2: 
                        riskStr = "MEDIUM";
                        mediumRiskCount++;
                        break;
                    case 1: 
                        riskStr = "LOW";
                        lowRiskCount++;
                        break;
                    default: 
                        riskStr = "NONE";
                        break;
                }

                // Print base thread info
                std::cout << std::left
                        << std::setw(8) << thread.ThreadId
                        << std::setw(8) << thread.ProcessId
                        << std::setw(18) << "0x" << std::hex << thread.StartAddress << std::dec
                        << std::setw(8) << thread.CreatorProcessId
                        << std::setw(7) << (thread.IsRemoteThread ? "Yes" : "No")
                        << std::setw(8) << riskStr
                        << WStringToString(FormatTime(thread.CreationTime));

                // Print flags if present
                if (thread.Flags != 0) {
                    std::cout << std::endl << std::string(57, ' ') << "Flags: ";
                    
                    if (thread.Flags & THREAD_FLAG_REMOTE_CREATED)
                        std::cout << "[Remote] ";
                    if (thread.Flags & THREAD_FLAG_SUSPICIOUS_ADDRESS)
                        std::cout << "[Suspicious Address] ";
                    if (thread.Flags & THREAD_FLAG_NOT_IN_IMAGE)
                        std::cout << "[Not In Module] ";
                    if (thread.Flags & THREAD_FLAG_SUSPICIOUS_TIMING)
                        std::cout << "[Suspicious Timing] ";
                    if (thread.Flags & THREAD_FLAG_SUSPENDED)
                        std::cout << "[Suspended] ";
                    if (thread.Flags & THREAD_FLAG_INJECTION_PATTERN)
                        std::cout << "[INJECTION PATTERN] ";
                }

                std::cout << std::endl;
                
                // Add separator for high risk items
                if (thread.RiskLevel == 3) {
                    std::cout << std::string(120, '=') << std::endl;
                }
            }

            std::cout << std::endl
                    << "Total threads: " << pList->Count
                    << (ProcessId ? std::string(" for process ") + std::to_string(ProcessId) : "")
                    << std::endl;

            // Print risk summary
            if (highRiskCount > 0 || mediumRiskCount > 0) {
                std::cout << std::endl << "Risk Summary:" << std::endl;
                std::cout << "--------------" << std::endl;
                
                if (highRiskCount > 0) {
                    std::cout << "HIGH RISK threads: " << highRiskCount << std::endl;
                }
                
                if (mediumRiskCount > 0) {
                    std::cout << "MEDIUM RISK threads: " << mediumRiskCount << std::endl;
                }
                
                if (lowRiskCount > 0) {
                    std::cout << "LOW RISK threads: " << lowRiskCount << std::endl;
                }
                
                // Print security recommendations for high risk items
                if (highRiskCount > 0) {
                    std::cout << std::endl << "SECURITY RECOMMENDATIONS:" << std::endl;
                    std::cout << "-------------------------" << std::endl;
                    
                    if (highRiskCount > 0) {
                        std::cout << "* HIGH RISK threads with INJECTION PATTERN may indicate code injection attacks" << std::endl;
                        std::cout << "* Threads with suspicious start addresses may be executing shellcode or injected code" << std::endl;
                    }
                    
                    if (mediumRiskCount > 0) {
                        std::cout << "* Review MEDIUM RISK threads for unusual behavior, particularly remote threads" << std::endl;
                    }
                    
                    std::cout << "* Consider using process-info command for more detailed analysis of suspicious processes" << std::endl;
                }
            }
        }
    }
    else
    {
        std::cerr << "Failed to get thread creation history: " << GetLastErrorAsString() << std::endl;
    }

    delete[] buffer;
    CloseDriverHandle(hDevice);
}

// Command: alerts (with optional clear)
void CommandAlerts(bool ClearAlerts)
{
    HANDLE hDevice = OpenDriverHandle();
    if (hDevice == INVALID_HANDLE_VALUE)
    {
        return;
    }

    if (ClearAlerts)
    {
        // Clear alerts first
        DWORD bytesReturned = 0;
        BOOL success = DeviceIoControl(
            hDevice,
            IOCTL_CLEAR_ALERTS,
            NULL, 0,
            NULL, 0,
            &bytesReturned,
            NULL);

        if (success)
        {
            std::cout << "Alerts cleared successfully." << std::endl;
        }
        else
        {
            std::cerr << "Failed to clear alerts: " << GetLastErrorAsString() << std::endl;
            CloseDriverHandle(hDevice);
            return;
        }
    }

    // Get the alerts
    DWORD bytesReturned = 0;
    DWORD bufferSize = sizeof(ALERT_LIST); // Minimum size for count
    BYTE *buffer = nullptr;
    BOOL success = false;

    // Try first with a small buffer
    buffer = new BYTE[bufferSize];
    success = DeviceIoControl(
        hDevice,
        IOCTL_GET_ALERTS,
        NULL, 0,
        buffer, bufferSize,
        &bytesReturned,
        NULL);

    if (!success && GetLastError() == ERROR_INSUFFICIENT_BUFFER)
    {
        // Get the required size from the returned data
        PALERT_LIST pList = reinterpret_cast<PALERT_LIST>(buffer);
        bufferSize = sizeof(ALERT_LIST) + (pList->Count - 1) * sizeof(ALERT_INFO);

        // Reallocate buffer with correct size
        delete[] buffer;
        buffer = new BYTE[bufferSize];

        // Try again with correctly sized buffer
        success = DeviceIoControl(
            hDevice,
            IOCTL_GET_ALERTS,
            NULL, 0,
            buffer, bufferSize,
            &bytesReturned,
            NULL);
    }

    if (success)
    {
        PALERT_LIST pList = reinterpret_cast<PALERT_LIST>(buffer);

        if (pList->Count == 0)
        {
            std::cout << "No alerts to display." << std::endl;
        }
        else
        {
            // Print header
            std::cout << std::left << std::setw(6) << "ID"
                      << std::setw(25) << "Alert Type"
                      << std::setw(8) << "PID"
                      << std::setw(20) << "Timestamp"
                      << "Details" << std::endl;
            std::cout << std::string(100, '-') << std::endl;

            // Print each alert
            for (ULONG i = 0; i < pList->Count; i++)
            {
                ALERT_INFO &alert = pList->Alerts[i];

                // Get alert type string
                std::string alertType;
                switch (alert.Type)
                {
                case AlertTypeStackViolation:
                    alertType = "Stack Violation";
                    break;
                case AlertTypeFilterViolation:
                    alertType = "Registry Filter Violation";
                    break;
                case AlertTypeRemoteThreadCreation:
                    alertType = "Remote Thread Creation";
                    break;
                case AlertTypeParentProcessIdSpoofing:
                    alertType = "Parent PID Spoofing";
                    break;
                default:
                    alertType = "Unknown";
                    break;
                }

                std::cout << std::left
                          << std::setw(6) << alert.AlertId
                          << std::setw(25) << alertType
                          << std::setw(8) << alert.SourceProcessId
                          << std::setw(20) << WStringToString(FormatTime(alert.Timestamp))
                          << WStringToString(alert.SourcePath) << std::endl;

                // Print additional details based on alert type
                if (alert.Type == AlertTypeStackViolation)
                {
                    std::cout << std::string(6, ' ') << "Violating Address: " << std::hex << alert.ViolatingAddress << std::dec << std::endl;
                }
                else if (alert.Type == AlertTypeFilterViolation)
                {
                    std::cout << std::string(6, ' ') << "Registry Path: " << WStringToString(alert.TargetPath) << std::endl;
                }
                else if (alert.Type == AlertTypeRemoteThreadCreation || alert.Type == AlertTypeParentProcessIdSpoofing)
                {
                    std::cout << std::string(6, ' ') << "Target Process: " << alert.TargetProcessId
                              << " - " << WStringToString(alert.TargetPath) << std::endl;
                }

                // Add separator between alerts
                std::cout << std::string(59, '-') << std::endl;
            }

            std::cout << std::endl
                      << "Total alerts: " << pList->Count << std::endl;

            if (!ClearAlerts)
            {
                std::cout << "Use 'alerts clear' to clear these alerts." << std::endl;
            }
        }
    }
    else
    {
        std::cerr << "Failed to get alerts: " << GetLastErrorAsString() << std::endl;
    }

    delete[] buffer;
    CloseDriverHandle(hDevice);
}

// Command: protect-process
void CommandProtectProcess(ULONG ProcessId, bool Enable)
{
    HANDLE hDevice = OpenDriverHandle();
    if (hDevice == INVALID_HANDLE_VALUE)
    {
        return;
    }

    // Set up the request
    PROCESS_PROTECTION_REQUEST request;
    request.ProcessId = ProcessId;
    request.Enable = Enable;

    DWORD bytesReturned = 0;
    BOOL success = DeviceIoControl(
        hDevice,
        IOCTL_PROTECT_PROCESS,
        &request, sizeof(request),
        NULL, 0, // No output data needed
        &bytesReturned,
        NULL);

    if (success)
    {
        std::cout << "Process protection " << (Enable ? "enabled" : "disabled")
                  << " for PID " << ProcessId << std::endl;
    }
    else
    {
        std::cerr << "Failed to change process protection: " << GetLastErrorAsString() << std::endl;
    }

    CloseDriverHandle(hDevice);
}

// Command: system-stats
void CommandSystemStats()
{
    HANDLE hDevice = OpenDriverHandle();
    if (hDevice == INVALID_HANDLE_VALUE)
    {
        return;
    }

    SYSTEM_STATS stats;
    DWORD bytesReturned = 0;
    BOOL success = DeviceIoControl(
        hDevice,
        IOCTL_GET_SYSTEM_STATS,
        NULL, 0,
        &stats, sizeof(stats),
        &bytesReturned,
        NULL);

    if (success)
    {
        // Convert uptime to hours, minutes, seconds
        ULONGLONG seconds = stats.DriverUptime.QuadPart / 10000000; // Convert from 100-nanosecond to seconds
        ULONGLONG hours = seconds / 3600;
        ULONGLONG minutes = (seconds % 3600) / 60;
        ULONGLONG remainingSeconds = seconds % 60;

        std::cout << "GPDriver System Statistics" << std::endl;
        std::cout << "=========================" << std::endl;
        std::cout << "Driver Uptime:              " << hours << "h " << minutes << "m " << remainingSeconds << "s" << std::endl;
        std::cout << "Driver Memory Usage:        " << stats.DriverMemoryUsage / 1024 << " KB" << std::endl;
        std::cout << "Total Processes Monitored:  " << stats.TotalProcessesMonitored << std::endl;
        std::cout << "Currently Active Processes: " << stats.ActiveProcesses << std::endl;
        std::cout << "Registry Operations Blocked:" << stats.RegistryOperationsBlocked << std::endl;
        std::cout << "Registry Filters Count:     " << stats.RegistryFiltersCount << std::endl;
        std::cout << "Threads Monitored:          " << stats.ThreadsMonitored << std::endl;
        std::cout << "Remote Threads Detected:    " << stats.RemoteThreadsDetected << std::endl;
        std::cout << "Images Monitored:           " << stats.ImagesMonitored << std::endl;
        std::cout << "Remote Images Detected:     " << stats.RemoteImagesDetected << std::endl;
        std::cout << "Total Alerts Generated:     " << stats.TotalAlertsGenerated << std::endl;
        std::cout << "Pending Alerts:             " << stats.PendingAlerts << std::endl;
    }
    else
    {
        std::cerr << "Failed to get system statistics: " << GetLastErrorAsString() << std::endl;
    }

    CloseDriverHandle(hDevice);
}

// Command: export-csv
void CommandExportCsv(const std::string &Filename, const std::string &Command)
{
    if (Command == "process-list")
    {
        ExportProcessListToCsv(Filename);
    }
    else if (Command == "registry-monitor")
    {
        ExportRegistryActivityToCsv(Filename);
    }
    else if (Command == "dll-monitor")
    {
        ExportDllMonitorToCsv(Filename);
    }
    else if (Command == "thread-monitor")
    {
        ExportThreadMonitorToCsv(Filename);
    }
    else if (Command == "alerts")
    {
        ExportAlertsToCsv(Filename);
    }
}

// Helper function to export process list to CSV
void ExportProcessListToCsv(const std::string &Filename)
{
    HANDLE hDevice = OpenDriverHandle();
    if (hDevice == INVALID_HANDLE_VALUE)
    {
        return;
    }

    // First get the size needed
    DWORD bytesReturned = 0;
    DWORD bufferSize = sizeof(PROCESS_LIST); // Minimum size for count
    BYTE *buffer = nullptr;
    BOOL success = false;

    // Try first with a small buffer
    buffer = new BYTE[bufferSize];
    success = DeviceIoControl(
        hDevice,
        IOCTL_GET_PROCESS_LIST,
        NULL, 0,
        buffer, bufferSize,
        &bytesReturned,
        NULL);

    if (!success && GetLastError() == ERROR_INSUFFICIENT_BUFFER)
    {
        // Get the required size from the returned data
        PPROCESS_LIST pList = reinterpret_cast<PPROCESS_LIST>(buffer);
        bufferSize = sizeof(PROCESS_LIST) + (pList->Count - 1) * sizeof(PROCESS_INFO);

        // Reallocate buffer with correct size
        delete[] buffer;
        buffer = new BYTE[bufferSize];

        // Try again with correctly sized buffer
        success = DeviceIoControl(
            hDevice,
            IOCTL_GET_PROCESS_LIST,
            NULL, 0,
            buffer, bufferSize,
            &bytesReturned,
            NULL);
    }

    if (success)
    {
        // Open CSV file
        std::ofstream csvFile(Filename);
        if (!csvFile.is_open())
        {
            std::cerr << "Failed to open file: " << Filename << std::endl;
            delete[] buffer;
            CloseDriverHandle(hDevice);
            return;
        }

        // Write CSV header
        csvFile << "PID,PPID,ImageName,CreationTime,IsTerminated" << std::endl;

        // Write process data
        PPROCESS_LIST pList = reinterpret_cast<PPROCESS_LIST>(buffer);
        for (ULONG i = 0; i < pList->Count; i++)
        {
            PROCESS_INFO &proc = pList->Processes[i];

            // Extract filename from full path
            std::wstring fullPath = proc.ImagePath;
            size_t lastSlash = fullPath.find_last_of(L"\\");
            std::wstring fileName = (lastSlash != std::wstring::npos) ? fullPath.substr(lastSlash + 1) : fullPath;

            // Format time for CSV
            std::wstring timeStr = FormatTime(proc.CreationTime);

            // Write CSV line
            csvFile << proc.ProcessId << ","
                    << proc.ParentProcessId << ","
                    << "\"" << WStringToString(fileName) << "\","
                    << "\"" << WStringToString(timeStr) << "\","
                    << (proc.IsTerminated ? "Yes" : "No") << std::endl;
        }

        csvFile.close();
        std::cout << "Process list exported to " << Filename << std::endl;
        std::cout << "Total processes: " << pList->Count << std::endl;
    }
    else
    {
        std::cerr << "Failed to get process list: " << GetLastErrorAsString() << std::endl;
    }

    delete[] buffer;
    CloseDriverHandle(hDevice);
}

// Helper function to export registry activity to CSV
void ExportRegistryActivityToCsv(const std::string &Filename)
{
    HANDLE hDevice = OpenDriverHandle();
    if (hDevice == INVALID_HANDLE_VALUE)
    {
        return;
    }

    // Request a reasonable number of registry activities
    ULONG Count = 1000;

    // Allocate a buffer for the results
    DWORD bufferSize = sizeof(REGISTRY_ACTIVITY_LIST) + (Count - 1) * sizeof(REGISTRY_ACTIVITY);
    BYTE *buffer = new BYTE[bufferSize];
    DWORD bytesReturned = 0;

    BOOL success = DeviceIoControl(
        hDevice,
        IOCTL_GET_REGISTRY_ACTIVITY,
        &Count, sizeof(Count), // Pass count as input
        buffer, bufferSize,
        &bytesReturned,
        NULL);

    if (success)
    {
        // Open CSV file
        std::ofstream csvFile(Filename);
        if (!csvFile.is_open())
        {
            std::cerr << "Failed to open file: " << Filename << std::endl;
            delete[] buffer;
            CloseDriverHandle(hDevice);
            return;
        }

        // Write CSV header
        csvFile << "PID,ProcessName,OperationType,Timestamp,RegistryPath" << std::endl;

        // Write registry activity data
        PREGISTRY_ACTIVITY_LIST pList = reinterpret_cast<PREGISTRY_ACTIVITY_LIST>(buffer);
        for (ULONG i = 0; i < pList->Count; i++)
        {
            REGISTRY_ACTIVITY &activity = pList->Activities[i];

            // Map operation type to string
            std::string opType;
            switch (activity.OperationType)
            {
            case 0:
                opType = "Read";
                break;
            case 1:
                opType = "Write";
                break;
            case 2:
                opType = "Delete";
                break;
            case 3:
                opType = "Create";
                break;
            default:
                opType = "Unknown";
                break;
            }

            // Extract process name from full path
            std::wstring procPath = activity.ProcessName;
            size_t lastSlash = procPath.find_last_of(L"\\");
            std::wstring procName = (lastSlash != std::wstring::npos) ? procPath.substr(lastSlash + 1) : procPath;

            // Format time for CSV
            std::wstring timeStr = FormatTime(activity.Timestamp);

            // Write CSV line
            csvFile << activity.ProcessId << ","
                    << "\"" << WStringToString(procName) << "\","
                    << "\"" << opType << "\","
                    << "\"" << WStringToString(timeStr) << "\","
                    << "\"" << WStringToString(activity.RegistryPath) << "\"" << std::endl;
        }

        csvFile.close();
        std::cout << "Registry activity exported to " << Filename << std::endl;
        std::cout << "Total registry operations: " << pList->Count << std::endl;
    }
    else
    {
        std::cerr << "Failed to get registry activity: " << GetLastErrorAsString() << std::endl;
    }

    delete[] buffer;
    CloseDriverHandle(hDevice);
}

// Helper function to export DLL monitor data to CSV
void ExportDllMonitorToCsv(const std::string &Filename)
{
    HANDLE hDevice = OpenDriverHandle();
    if (hDevice == INVALID_HANDLE_VALUE)
    {
        return;
    }

    // Request all processes (PID = 0)
    ULONG ProcessId = 0;

    // First get the size needed
    DWORD bytesReturned = 0;
    DWORD bufferSize = sizeof(IMAGE_LOAD_LIST); // Minimum size for count
    BYTE *buffer = nullptr;
    BOOL success = false;

    // Try first with a small buffer
    buffer = new BYTE[bufferSize];
    success = DeviceIoControl(
        hDevice,
        IOCTL_GET_IMAGE_LOAD_HISTORY,
        &ProcessId, sizeof(ProcessId),
        buffer, bufferSize,
        &bytesReturned,
        NULL);

    if (!success && GetLastError() == ERROR_INSUFFICIENT_BUFFER)
    {
        // Get the required size from the returned data
        PIMAGE_LOAD_LIST pList = reinterpret_cast<PIMAGE_LOAD_LIST>(buffer);
        bufferSize = sizeof(IMAGE_LOAD_LIST) + (pList->Count - 1) * sizeof(IMAGE_LOAD_INFO);

        // Reallocate buffer with correct size
        delete[] buffer;
        buffer = new BYTE[bufferSize];

        // Try again with correctly sized buffer
        success = DeviceIoControl(
            hDevice,
            IOCTL_GET_IMAGE_LOAD_HISTORY,
            &ProcessId, sizeof(ProcessId),
            buffer, bufferSize,
            &bytesReturned,
            NULL);
    }

    if (success)
    {
        // Open CSV file
        std::ofstream csvFile(Filename);
        if (!csvFile.is_open())
        {
            std::cerr << "Failed to open file: " << Filename << std::endl;
            delete[] buffer;
            CloseDriverHandle(hDevice);
            return;
        }

        // Write CSV header
        csvFile << "PID,BaseAddress,ImageSize,RemoteLoad,CallerProcessId,LoadTime,ImagePath" << std::endl;

        // Write image load data
        PIMAGE_LOAD_LIST pList = reinterpret_cast<PIMAGE_LOAD_LIST>(buffer);
        for (ULONG i = 0; i < pList->Count; i++)
        {
            IMAGE_LOAD_INFO &img = pList->LoadedImages[i];

            // Format time for CSV
            std::wstring timeStr = FormatTime(img.LoadTime);

            // Write CSV line
            csvFile << img.ProcessId << ","
                    << "0x" << std::hex << img.ImageBase << std::dec << ","
                    << img.ImageSize << ","
                    << (img.RemoteLoad ? "Yes" : "No") << ","
                    << img.CallerProcessId << ","
                    << "\"" << WStringToString(timeStr) << "\","
                    << "\"" << WStringToString(img.ImagePath) << "\"" << std::endl;
        }

        csvFile.close();
        std::cout << "Image load history exported to " << Filename << std::endl;
        std::cout << "Total loaded images: " << pList->Count << std::endl;
    }
    else
    {
        std::cerr << "Failed to get image load history: " << GetLastErrorAsString() << std::endl;
    }

    delete[] buffer;
    CloseDriverHandle(hDevice);
}

// Helper function to export thread monitor data to CSV
void ExportThreadMonitorToCsv(const std::string &Filename)
{
    HANDLE hDevice = OpenDriverHandle();
    if (hDevice == INVALID_HANDLE_VALUE)
    {
        return;
    }

    // Request all processes (PID = 0)
    ULONG ProcessId = 0;

    // First get the size needed
    DWORD bytesReturned = 0;
    DWORD bufferSize = sizeof(THREAD_LIST); // Minimum size for count
    BYTE *buffer = nullptr;
    BOOL success = false;

    // Try first with a small buffer
    buffer = new BYTE[bufferSize];
    success = DeviceIoControl(
        hDevice,
        IOCTL_GET_THREAD_CREATION_HISTORY,
        &ProcessId, sizeof(ProcessId),
        buffer, bufferSize,
        &bytesReturned,
        NULL);

    if (!success && GetLastError() == ERROR_INSUFFICIENT_BUFFER)
    {
        // Get the required size from the returned data
        PTHREAD_LIST pList = reinterpret_cast<PTHREAD_LIST>(buffer);
        bufferSize = sizeof(THREAD_LIST) + (pList->Count - 1) * sizeof(THREAD_INFO);

        // Reallocate buffer with correct size
        delete[] buffer;
        buffer = new BYTE[bufferSize];

        // Try again with correctly sized buffer
        success = DeviceIoControl(
            hDevice,
            IOCTL_GET_THREAD_CREATION_HISTORY,
            &ProcessId, sizeof(ProcessId),
            buffer, bufferSize,
            &bytesReturned,
            NULL);
    }

    if (success)
    {
        // Open CSV file
        std::ofstream csvFile(Filename);
        if (!csvFile.is_open())
        {
            std::cerr << "Failed to open file: " << Filename << std::endl;
            delete[] buffer;
            CloseDriverHandle(hDevice);
            return;
        }

        // Write CSV header
        csvFile << "ThreadID,ProcessID,StartAddress,CreatorProcessID,IsRemoteThread,CreationTime" << std::endl;

        // Write thread data
        PTHREAD_LIST pList = reinterpret_cast<PTHREAD_LIST>(buffer);
        for (ULONG i = 0; i < pList->Count; i++)
        {
            THREAD_INFO &thread = pList->Threads[i];

            // Format time for CSV
            std::wstring timeStr = FormatTime(thread.CreationTime);

            // Write CSV line
            csvFile << thread.ThreadId << ","
                    << thread.ProcessId << ","
                    << "0x" << std::hex << thread.StartAddress << std::dec << ","
                    << thread.CreatorProcessId << ","
                    << (thread.IsRemoteThread ? "Yes" : "No") << ","
                    << "\"" << WStringToString(timeStr) << "\"" << std::endl;
        }

        csvFile.close();
        std::cout << "Thread creation history exported to " << Filename << std::endl;
        std::cout << "Total threads: " << pList->Count << std::endl;
    }
    else
    {
        std::cerr << "Failed to get thread creation history: " << GetLastErrorAsString() << std::endl;
    }

    delete[] buffer;
    CloseDriverHandle(hDevice);
}

// Helper function to export alerts to CSV
void ExportAlertsToCsv(const std::string &Filename)
{
    HANDLE hDevice = OpenDriverHandle();
    if (hDevice == INVALID_HANDLE_VALUE)
    {
        return;
    }

    // Get the alerts
    DWORD bytesReturned = 0;
    DWORD bufferSize = sizeof(ALERT_LIST); // Minimum size for count
    BYTE *buffer = nullptr;
    BOOL success = false;

    // Try first with a small buffer
    buffer = new BYTE[bufferSize];
    success = DeviceIoControl(
        hDevice,
        IOCTL_GET_ALERTS,
        NULL, 0,
        buffer, bufferSize,
        &bytesReturned,
        NULL);

    if (!success && GetLastError() == ERROR_INSUFFICIENT_BUFFER)
    {
        // Get the required size from the returned data
        PALERT_LIST pList = reinterpret_cast<PALERT_LIST>(buffer);
        bufferSize = sizeof(ALERT_LIST) + (pList->Count - 1) * sizeof(ALERT_INFO);

        // Reallocate buffer with correct size
        delete[] buffer;
        buffer = new BYTE[bufferSize];

        // Try again with correctly sized buffer
        success = DeviceIoControl(
            hDevice,
            IOCTL_GET_ALERTS,
            NULL, 0,
            buffer, bufferSize,
            &bytesReturned,
            NULL);
    }

    if (success)
    {
        // Open CSV file
        std::ofstream csvFile(Filename);
        if (!csvFile.is_open())
        {
            std::cerr << "Failed to open file: " << Filename << std::endl;
            delete[] buffer;
            CloseDriverHandle(hDevice);
            return;
        }

        // Write CSV header
        csvFile << "AlertID,AlertType,SourceProcessID,Timestamp,ViolatingAddress,TargetProcessID,SourcePath,TargetPath" << std::endl;

        // Write alert data
        PALERT_LIST pList = reinterpret_cast<PALERT_LIST>(buffer);
        for (ULONG i = 0; i < pList->Count; i++)
        {
            ALERT_INFO &alert = pList->Alerts[i];

            // Get alert type string
            std::string alertType;
            switch (alert.Type)
            {
            case AlertTypeStackViolation:
                alertType = "Stack Violation";
                break;
            case AlertTypeFilterViolation:
                alertType = "Registry Filter Violation";
                break;
            case AlertTypeRemoteThreadCreation:
                alertType = "Remote Thread Creation";
                break;
            case AlertTypeParentProcessIdSpoofing:
                alertType = "Parent PID Spoofing";
                break;
            default:
                alertType = "Unknown";
                break;
            }

            // Format time for CSV
            std::wstring timeStr = FormatTime(alert.Timestamp);

            // Write CSV line
            csvFile << alert.AlertId << ","
                    << "\"" << alertType << "\","
                    << alert.SourceProcessId << ","
                    << "\"" << WStringToString(timeStr) << "\","
                    << "0x" << std::hex << alert.ViolatingAddress << std::dec << ","
                    << alert.TargetProcessId << ","
                    << "\"" << WStringToString(alert.SourcePath) << "\","
                    << "\"" << WStringToString(alert.TargetPath) << "\"" << std::endl;
        }

        csvFile.close();
        std::cout << "Alerts exported to " << Filename << std::endl;
        std::cout << "Total alerts: " << pList->Count << std::endl;
    }
    else
    {
        std::cerr << "Failed to get alerts: " << GetLastErrorAsString() << std::endl;
    }

    delete[] buffer;
    CloseDriverHandle(hDevice);
}