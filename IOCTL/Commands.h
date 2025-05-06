#pragma once
#include <Windows.h>
#include <string>

// Utility functions for string and time conversion
std::wstring FormatTime(const LARGE_INTEGER& time);
std::wstring StringToWString(const std::string& str);
std::string WStringToString(const std::wstring& wstr);

// Device handle management functions
HANDLE OpenDriverHandle();
void CloseDriverHandle(HANDLE hDevice);

// Command functions
void CommandProcessList();
void CommandProcessInfo(ULONG ProcessId);
void CommandRegistryMonitor(ULONG Count);
void CommandAddRegistryFilter(const std::wstring& RegistryPath, ULONG FilterFlags);
void CommandDllMonitor(ULONG ProcessId);
void CommandThreadMonitor(ULONG ProcessId);
void CommandAlerts(bool ClearAlerts);
void CommandProtectProcess(ULONG ProcessId, bool Enable);
void CommandSystemStats();
void CommandExportCsv(const std::string& Filename, const std::string& Command);

// Helper functions for exporting data to CSV
void ExportProcessListToCsv(const std::string& Filename);
void ExportRegistryActivityToCsv(const std::string& Filename);
void ExportDllMonitorToCsv(const std::string& Filename);
void ExportThreadMonitorToCsv(const std::string& Filename);
void ExportAlertsToCsv(const std::string& Filename);
