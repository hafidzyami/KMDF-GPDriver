/*
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE', which is part of this source code package.
 * 
 * COPYRIGHT Bill Demirkapi 2020
 */
#pragma once

#include "common.h"
#include "StringFilters.h"
#include "StackWalker.h"
#include "DetectionLogic.h"
#include "ImageFilter.h"

// Forward declaration of RegistryAnalyzer class
class RegistryAnalyzer;

// Define a pointer type for RegistryAnalyzer
typedef class RegistryAnalyzer* PREGISTRY_ANALYZER;

#include "RegistryAnalyzer.h"
#include "shared.h"

// Registry Filter tags
#define STRING_REGISTRY_FILTERS_TAG 'rFmP'
#define REGISTRY_KEY_NAME_TAG 'nKmP'

// Process/Thread access constants
#define PROCESS_TERMINATE (0x0001)  
#define THREAD_TERMINATE (0x0001)

/*
 * Object filter class for registry and process protection
 */
class ObjectFilter
{
private:
    // Registry Filter components
    static BOOLEAN BlockRegistryOperation(
        _In_ PVOID KeyObject,
        _In_ PUNICODE_STRING ValueName,
        _In_ ULONG OperationFlag
        );

    static NTSTATUS RegistryCallback(
        _In_ PVOID CallbackContext,
        _In_ REG_NOTIFY_CLASS OperationClass,
        _In_ PVOID Argument2
        );

    // Contains strings to block various registry operations
    static PSTRING_FILTERS RegistryStringFilters;

    // Cookie used to remove registry callback
    static LARGE_INTEGER RegistryFilterCookie;

    static STACK_WALKER walker;
    static PDETECTION_LOGIC detector;

    // Registry behavior analyzer for malware detection
    static PREGISTRY_ANALYZER registryAnalyzer;

    // Tamper Guard components
    static OB_PREOP_CALLBACK_STATUS PreOperationCallback(
        _In_ PVOID RegistrationContext,
        _In_ POB_PRE_OPERATION_INFORMATION OperationInformation
        );
    OB_CALLBACK_REGISTRATION ObRegistrationInformation;
    OB_OPERATION_REGISTRATION ObOperationRegistration[2];
    PVOID RegistrationHandle;

    static HANDLE ProtectedProcessId;

public:
    ObjectFilter(
        _In_ PDRIVER_OBJECT DriverObject,
        _In_ PUNICODE_STRING RegistryPath,
        _In_ PDETECTION_LOGIC Detector,
        _Out_ NTSTATUS* InitializeStatus
        );
    ~ObjectFilter();

    static PSTRING_FILTERS GetRegistryStringFilters();
    
    VOID UpdateProtectedProcess(
        _In_ HANDLE NewProcessId
        );

    PREGISTRY_ANALYZER GetRegistryAnalyzer()
    {
        return registryAnalyzer;
    }
};

// Type definitions for easier usage
typedef ObjectFilter OBJECT_FILTER;
typedef OBJECT_FILTER* POBJECT_FILTER;
