/*
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE', which is part of this source code package.
 * 
 * COPYRIGHT Hafidz S 2025
 */
#include "pch.h"
#include "StackWalker.h"

/**
	Search the current process to see if any modules contain the address.
	@param Address - The address to search for.
	@param StackReturnInfo - The structure to be populated.
*/
VOID
StackWalker::ResolveAddressModule (
    _In_ PVOID Address,
    _Inout_ PSTACK_RETURN_INFO StackReturnInfo
    )
{
    NTSTATUS status;
    MEMORY_BASIC_INFORMATION meminfo;
    SIZE_T returnLength;
    SIZE_T mappedFilenameLength;
    PUNICODE_STRING mappedFilename = NULL;

    // Don't try to resolve NULL or invalid addresses
    if (Address == NULL || (ULONG_PTR)Address >= (ULONG_PTR)MmHighestUserAddress) {
        return;
    }

    mappedFilenameLength = sizeof(UNICODE_STRING) + MAX_PATH * 2;
    __try {
        //
        // Query the virtual memory to see if it's part of an image.
        //
        status = ZwQueryVirtualMemory(NtCurrentProcess(), Address, MemoryBasicInformation, &meminfo, sizeof(meminfo), &returnLength);
        if (NT_SUCCESS(status) && meminfo.Type == MEM_IMAGE)
        {
            StackReturnInfo->MemoryInModule = TRUE;
            StackReturnInfo->BinaryOffset = RCAST<ULONG64>(Address) - RCAST<ULONG64>(meminfo.AllocationBase);

            //
            // Allocate the filename using non-paged pool for higher IRQL support.
            //
            mappedFilename = RCAST<PUNICODE_STRING>(ExAllocatePool2(POOL_FLAG_NON_PAGED, mappedFilenameLength, STACK_WALK_MAPPED_NAME));
            if (mappedFilename == NULL)
            {
                DBGPRINT("StackWalker!ResolveAddressModule: Failed to allocate module name.");
                return;
            }

            // Zero out the memory to prevent issues with uninitialized data
            memset(mappedFilename, 0, mappedFilenameLength);

            //
            // Query the filename.
            //
            status = ZwQueryVirtualMemory(NtCurrentProcess(), 
                                         Address, 
                                         SCAST<MEMORY_INFORMATION_CLASS>(MemoryMappedFilenameInformation), 
                                         mappedFilename, 
                                         mappedFilenameLength, 
                                         &mappedFilenameLength);
            
            if (status == STATUS_BUFFER_OVERFLOW)
            {
                //
                // If we don't have a large enough buffer, allocate one!
                //
                ExFreePoolWithTag(mappedFilename, STACK_WALK_MAPPED_NAME);
                mappedFilename = RCAST<PUNICODE_STRING>(ExAllocatePool2(POOL_FLAG_NON_PAGED, 
                                                       mappedFilenameLength, 
                                                       STACK_WALK_MAPPED_NAME));
                if (mappedFilename == NULL)
                {
                    DBGPRINT("StackWalker!ResolveAddressModule: Failed to allocate module name.");
                    return;
                }
                
                // Zero out the memory to prevent issues with uninitialized data
                memset(mappedFilename, 0, mappedFilenameLength);
                
                status = ZwQueryVirtualMemory(NtCurrentProcess(), 
                                             Address, 
                                             SCAST<MEMORY_INFORMATION_CLASS>(MemoryMappedFilenameInformation), 
                                             mappedFilename, 
                                             mappedFilenameLength, 
                                             &mappedFilenameLength);
            }

            if (NT_SUCCESS(status) == FALSE)
            {
                DBGPRINT("StackWalker!ResolveAddressModule: Failed to query memory module name with status 0x%X.", status);
                ExFreePoolWithTag(mappedFilename, STACK_WALK_MAPPED_NAME);
                return;
            }

            //
            // Copy the mapped name.
            //
            if (mappedFilename->Buffer && mappedFilename->Length > 0) {
                // Safely copy the string with proper bounds checking
                __try {
                    RtlStringCbCopyUnicodeString(RCAST<NTSTRSAFE_PWSTR>(&StackReturnInfo->BinaryPath), 
                                               sizeof(StackReturnInfo->BinaryPath), 
                                               mappedFilename);
                }
                __except(EXCEPTION_EXECUTE_HANDLER) {
                    DBGPRINT("StackWalker!ResolveAddressModule: Exception copying mapped name: 0x%X", 
                             GetExceptionCode());
                }
            }

            if (mappedFilename != NULL) {
                ExFreePoolWithTag(mappedFilename, STACK_WALK_MAPPED_NAME);
                mappedFilename = NULL;
            }
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        DBGPRINT("StackWalker!ResolveAddressModule: Exception resolving address 0x%llx: 0x%X", 
                 RCAST<ULONG64>(Address), GetExceptionCode());
                 
        // Ensure we free the allocation if an exception occurred
        if (mappedFilename != NULL) {
            ExFreePoolWithTag(mappedFilename, STACK_WALK_MAPPED_NAME);
        }
    }
}

/**
	Check if the memory pointed by address is executable.
	@param Address - The address to check.
	@return Whether or not the memory is executable.
*/
BOOLEAN
StackWalker::IsAddressExecutable (
    _In_ PVOID Address
    )
{
    NTSTATUS status;
    MEMORY_BASIC_INFORMATION memoryBasicInformation;
    BOOLEAN executable = FALSE;

    memset(&memoryBasicInformation, 0, sizeof(memoryBasicInformation));

    // Don't try to query invalid addresses
    if (Address == NULL || (ULONG_PTR)Address >= (ULONG_PTR)MmHighestUserAddress) {
        return FALSE;
    }

    __try {
        //
        // Query the basic information about the memory.
        //
        status = ZwQueryVirtualMemory(NtCurrentProcess(), 
                                     Address, 
                                     MemoryBasicInformation, 
                                     &memoryBasicInformation, 
                                     sizeof(memoryBasicInformation), 
                                     NULL);
                                     
        if (NT_SUCCESS(status) == FALSE)
        {
            DBGPRINT("StackWalker!IsAddressExecutable: Failed to query virtual memory for address 0x%llx with status 0x%X.", 
                     RCAST<ULONG64>(Address), status);
            return FALSE;
        }

        //
        // Check if the protection flags specify executable.
        //
        executable = FlagOn(memoryBasicInformation.AllocationProtect, PAGE_EXECUTE) ||
                 FlagOn(memoryBasicInformation.AllocationProtect, PAGE_EXECUTE_READ) ||
                 FlagOn(memoryBasicInformation.AllocationProtect, PAGE_EXECUTE_READWRITE) ||
                 FlagOn(memoryBasicInformation.AllocationProtect, PAGE_EXECUTE_WRITECOPY);
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        DBGPRINT("StackWalker!IsAddressExecutable: Exception checking address 0x%llx: 0x%X", 
                 RCAST<ULONG64>(Address), GetExceptionCode());
        executable = FALSE;
    }

    return executable;
}

/**
	Walk the stack of the current thread and resolve the module associated with the return addresses.
	@param ResolvedStack - Caller-supplied array of return address information that this function populates.
	@param ResolvedStackSize - The number of return addresses to resolve.
	@param ResolvedStackTag - The tag to allocate ResolvedStack with.
*/
VOID
StackWalker::WalkAndResolveStack (
    _Inout_ PSTACK_RETURN_INFO* ResolvedStack,
    _Inout_ ULONG* ResolvedStackSize,
    _In_ ULONG ResolvedStackTag
    )
{
    // Initialize to NULL to avoid warning C4701
    PVOID* stackReturnPtrs = NULL;
    ULONG capturedReturnPtrs = 0;
    ULONG i = 0;
    
    capturedReturnPtrs = 0;
    *ResolvedStack = NULL;

    // Check if we can do stack walking at the current IRQL
    // Stack walking is only reliable at PASSIVE_LEVEL
    if (KeGetCurrentIrql() > PASSIVE_LEVEL) {
        DBGPRINT("StackWalker!WalkAndResolveStack: IRQL too high (%d) for reliable stack walking, will create minimal stack", 
                 KeGetCurrentIrql());
        
        // Provide a minimal dummy stack entry to avoid null pointers
        *ResolvedStack = RCAST<PSTACK_RETURN_INFO>(ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(STACK_RETURN_INFO), ResolvedStackTag));
        if (*ResolvedStack != NULL) {
            memset(*ResolvedStack, 0, sizeof(STACK_RETURN_INFO));
            (*ResolvedStack)[0].MemoryInModule = TRUE; // Mark as valid module
            *ResolvedStackSize = 1; // Set size to 1 to avoid null pointer issues
        } else {
            // If allocation failed, set size to 0
            *ResolvedStackSize = 0;
        }
        return;
    }

    // Limit the maximum stack size to prevent excessive memory usage
    if (*ResolvedStackSize > 128) {
        *ResolvedStackSize = 128;
    }

    //
    // Allocate space for the return addresses from NonPagedPool which works at higher IRQLs
    //
    stackReturnPtrs = RCAST<PVOID*>(ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(PVOID) * *ResolvedStackSize, STACK_WALK_ARRAY_TAG));
    if (stackReturnPtrs == NULL)
    {
        DBGPRINT("StackWalker!WalkAndResolveStack: Failed to allocate space for temporary stack array.");
        *ResolvedStackSize = 0;
        return;
    }

    memset(stackReturnPtrs, 0, sizeof(PVOID) * *ResolvedStackSize);

    __try {
        //
        // Get the return addresses leading up to this call.
        //
        capturedReturnPtrs = RtlWalkFrameChain(stackReturnPtrs, *ResolvedStackSize, 1);
        if (capturedReturnPtrs == 0)
        {
            DBGPRINT("StackWalker!WalkAndResolveStack: Failed to walk the stack.");
            goto Exit;
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        DBGPRINT("StackWalker!WalkAndResolveStack: Exception during RtlWalkFrameChain: 0x%X", GetExceptionCode());
        goto Exit;
    }

    // Ensure we don't overflow
    NT_ASSERT((ULONGLONG)capturedReturnPtrs <= (ULONGLONG)*ResolvedStackSize);

    // Update the size to the actual number of frames captured
    *ResolvedStackSize = capturedReturnPtrs;

    // If we didn't capture any frames, exit early
    if (capturedReturnPtrs == 0) {
        goto Exit;
    }

    //
    // Allocate space for the stack return info array using NonPagedPool for high IRQL compatibility
    //
    *ResolvedStack = RCAST<PSTACK_RETURN_INFO>(ExAllocatePool2(POOL_FLAG_NON_PAGED, 
                                               sizeof(STACK_RETURN_INFO) * *ResolvedStackSize, 
                                               ResolvedStackTag));
    if (*ResolvedStack == NULL)
    {
        DBGPRINT("StackWalker!WalkAndResolveStack: Failed to allocate space for stack info array.");
        goto Exit;
    }
    memset(*ResolvedStack, 0, sizeof(STACK_RETURN_INFO) * *ResolvedStackSize);

    //
    // Iterate each return address and fill out the struct.
    // Process addresses in smaller batches with exception handling for each batch
    //
    for (i = 0; i < capturedReturnPtrs; i += 8) {
        ULONG batchEnd = min(i + 8, capturedReturnPtrs);
        
        __try {
            for (ULONG j = i; j < batchEnd; j++) {
                (*ResolvedStack)[j].RawAddress = stackReturnPtrs[j];

                //
                // If the memory isn't executable or is in kernel, it's not worth our time.
                //
                if (RCAST<ULONG64>(stackReturnPtrs[j]) < MmUserProbeAddress && 
                    this->IsAddressExecutable(stackReturnPtrs[j]))
                {
                    (*ResolvedStack)[j].ExecutableMemory = TRUE;
                    this->ResolveAddressModule(stackReturnPtrs[j], &(*ResolvedStack)[j]);
                }
            }
        }
        __except(EXCEPTION_EXECUTE_HANDLER) {
            DBGPRINT("StackWalker!WalkAndResolveStack: Exception during stack analysis batch %d-%d: 0x%X", 
                     i, batchEnd, GetExceptionCode());
            // Continue with the next batch rather than abandoning the entire operation
        }
    }

Exit:
    // If we failed to create a valid stack and allocated nothing, create a minimal dummy entry
    if (*ResolvedStack == NULL) {
        *ResolvedStack = RCAST<PSTACK_RETURN_INFO>(ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(STACK_RETURN_INFO), ResolvedStackTag));
        if (*ResolvedStack != NULL) {
            memset(*ResolvedStack, 0, sizeof(STACK_RETURN_INFO));
            (*ResolvedStack)[0].MemoryInModule = TRUE; // Mark as valid module
            *ResolvedStackSize = 1; // Set size to 1 to avoid null pointer issues
        } else {
            *ResolvedStackSize = 0;
        }
    }

    if (stackReturnPtrs) {
        ExFreePoolWithTag(stackReturnPtrs, STACK_WALK_ARRAY_TAG);
    }
}