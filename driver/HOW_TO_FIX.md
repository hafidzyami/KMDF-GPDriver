# KMDF-GPDriver Fixes for Stack Walking Issues

This document explains the changes needed to fix the stack walking issues and VM hangs in the KMDF-GPDriver.

## Core Issues

1. **IRQL Level Problems**: Many driver failures occur due to trying to execute memory operations at elevated IRQL levels
2. **Insufficient Buffer Sizes**: The stack walker wasn't allocating enough space
3. **Paged Pool Usage**: The driver was using POOL_FLAG_PAGED for memory that needed to be accessed at elevated IRQL
4. **Lack of IRQL Checking**: Functions were not checking current IRQL before trying operations

## Fixed Files

I've created several fixed implementation files that you can use to replace the problematic sections:

1. `FixedLoadImageNotifyRoutine.cpp` - Fixed implementation for the LoadImageNotifyRoutine with DPC support
2. `FixedThreadNotifyRoutine.cpp` - Fixed implementation for ThreadNotifyRoutine
3. `FixedInitialize.cpp` - Fixed constructor for ImageFilter with DPC initialization
4. `FixedAddProcessThreadCount.cpp` - Fixed thread count function with IRQL checking
5. `FixedImageFilter.cpp` - Contains the DPC implementation to defer processing at high IRQL

## Key Changes

1. **DPC Implementation**: Added a deferred processing mechanism using DPCs (Deferred Procedure Calls) to handle processing at PASSIVE_LEVEL
2. **Non-Paged Pool**: Changed all memory allocations to use POOL_FLAG_NON_PAGED for high IRQL compatibility
3. **IRQL Checking**: Added checks to verify IRQL level before attempting operations
4. **Increased Buffer Sizes**: Changed MAX_STACK_RETURN_HISTORY from 30 to 64
5. **Early Returns**: Functions now exit early when at high IRQL instead of trying to continue

## How to Apply the Changes

1. In `shared.h`: Change MAX_STACK_RETURN_HISTORY from 30 to 64
2. In `StackWalker.cpp`: 
   - Add IRQL checks before operations
   - Change all memory allocations to use POOL_FLAG_NON_PAGED
   - Add proper exception handling
3. In `ImageFilter.cpp`:
   - Add the DPC implementation at the top
   - Fix the constructor to initialize the DPC
   - Update the LoadImageNotifyRoutine to use DPC for high IRQL
   - Update ThreadNotifyRoutine with IRQL checking

## Expected Results

After applying these changes:
- The driver will handle high IRQL situations properly
- Stack walking operations will be deferred to lower IRQL when needed
- Memory allocation will succeed even at higher IRQL levels
- The VM should no longer hang when processes start

If you continue to see issues after implementing these changes, check the debug output for any remaining errors related to IRQL levels or memory allocation failures.
