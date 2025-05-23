/*++
// Notice:
//    Use this sample code at your own risk; there is no support from Microsoft for the sample code.
//    In addition, this sample code is licensed to you under the terms of the Microsoft Public License
//    (http://www.microsoft.com/opensource/licenses.mspx)
--*/

#pragma once

#include <ntifs.h>
#include <ntddk.h>
#include <ntstrsafe.h>
#include <fltKernel.h>

// Tambahan header untuk C++
#ifdef __cplusplus
// Core headers
#include "common.h"
#include "IOCTLShared.h"

// Core components
#include "DetectionLogic.h"
#include "ImageFilter.h"
#include "ObjectFilter.h"
#include "AlertQueue.h"
#include "StringFilters.h"
#include "StackWalker.h"

// Extension components - added these last to avoid circular dependencies
#include "fixed_structures.h"
#include "AlertQueueExtension.h"
#endif
