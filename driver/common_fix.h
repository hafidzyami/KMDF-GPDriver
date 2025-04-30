/*
 * Common includes and definitions for KMDF driver
 * This is a fix file to ensure proper compilation
 */
#pragma once

#include <ntddk.h>
// #include <wdf.h> // Dinonaktifkan karena tidak tersedia
#include <fltKernel.h>
#include <ntstrsafe.h>

// External global references that need to be defined
extern POBJECT_TYPE* CmKeyObjectType;

// Common defines
#define MAX_PATH 260

// Common macros
#ifndef ARRAYSIZE
#define ARRAYSIZE(a) (sizeof(a)/sizeof(a[0]))
#endif
