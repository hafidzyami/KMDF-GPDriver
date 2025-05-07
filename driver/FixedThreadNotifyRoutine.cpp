VOID ImageFilter::ThreadNotifyRoutine(
	_In_ HANDLE ProcessId,
	_In_ HANDLE ThreadId,
	_In_ BOOLEAN Create)
{
	ULONG processThreadCount = 0;
	PVOID threadStartAddress = NULL; // Initialize to NULL
	PSTACK_RETURN_INFO threadCreateStack = NULL;
	ULONG threadCreateStackSize = 64; // Increased from 20 to 64
	PUNICODE_STRING threadCallerName = NULL; // Initialize to NULL
	PUNICODE_STRING threadTargetName = NULL;

	//
	// We don't really care about thread termination or if the thread is kernel-mode.
	//
	if (Create == FALSE || ExGetPreviousMode() == KernelMode)
	{
		return;
	}

	// Check IRQL level - we should only proceed at PASSIVE_LEVEL
	if (KeGetCurrentIrql() > PASSIVE_LEVEL) {
		DBGPRINT("ImageFilter!ThreadNotifyRoutine: Skipping due to high IRQL (%d)", KeGetCurrentIrql());
		return; // Skip at high IRQL instead of trying to allocate memory
	}

	//
	// If we can't find the process or it's the first thread of the process, skip it.
	//
	if (ImageFilter::AddProcessThreadCount(ProcessId, &processThreadCount) == FALSE ||
		processThreadCount <= 1)
	{
		return;
	}

	//
	// Walk the stack - use a larger buffer size
	//
	ImageFilter::walker.WalkAndResolveStack(&threadCreateStack, &threadCreateStackSize, STACK_HISTORY_TAG);
	// Continue even if stack walk fails
	if (threadCreateStack == NULL) {
		DBGPRINT("ImageFilter!ThreadNotifyRoutine: Failed to walk the stack, continuing without stack info.");
		threadCreateStackSize = 0;
	}

	//
	// Grab the name of the caller.
	//
	threadCallerName = NULL; // Initialize to NULL first
	if (ImageFilter::GetProcessImageFileName(PsGetCurrentProcessId(), &threadCallerName) == FALSE)
	{
		// Already initialized to NULL above
		goto Exit;
	}

	threadTargetName = threadCallerName;

	//
	// We only need to resolve again if the target process is a different than the caller.
	//
	if (PsGetCurrentProcessId() != ProcessId)
	{
		//
		// Grab the name of the target.
		//
		if (ImageFilter::GetProcessImageFileName(ProcessId, &threadTargetName) == FALSE)
		{
			goto Exit;
		}
	}

	//
	// Grab the start address of the thread.
	//
	threadStartAddress = ImageFilter::GetThreadStartAddress(ThreadId);

	// Only perform audits if we actually have stack information
	if (threadCreateStack != NULL && threadCreateStackSize > 0) {
		//
		// Audit the target's start address.
		//
		ImageFilter::detector->AuditUserPointer(ThreadCreate, threadStartAddress, PsGetCurrentProcessId(), threadCallerName, threadTargetName, threadCreateStack, threadCreateStackSize);

		//
		// Audit the caller's stack.
		//
		ImageFilter::detector->AuditUserStackWalk(ThreadCreate, PsGetCurrentProcessId(), threadCallerName, threadTargetName, threadCreateStack, threadCreateStackSize);

		//
		// Check if this is a remote operation.
		//
		ImageFilter::detector->AuditCallerProcessId(ThreadCreate, PsGetCurrentProcessId(), ProcessId, threadCallerName, threadTargetName, threadCreateStack, threadCreateStackSize);
	}
Exit:
	if (threadCreateStack != NULL)
	{
		ExFreePoolWithTag(threadCreateStack, STACK_HISTORY_TAG);
	}
	if (threadCallerName != NULL)
	{
		ExFreePoolWithTag(threadCallerName, IMAGE_NAME_TAG);
	}
	if (threadCallerName != threadTargetName && threadTargetName != NULL)
	{
		ExFreePoolWithTag(threadTargetName, IMAGE_NAME_TAG);
	}
}
