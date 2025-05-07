VOID ImageFilter::LoadImageNotifyRoutine(
	_In_ PUNICODE_STRING FullImageName,
	_In_ HANDLE ProcessId,
	_In_ PIMAGE_INFO ImageInfo)
{
	NTSTATUS status;
	PPROCESS_HISTORY_ENTRY currentProcessHistory;
	PIMAGE_LOAD_HISTORY_ENTRY newImageLoadHistory;

	UNREFERENCED_PARAMETER(ImageInfo);

	currentProcessHistory = NULL;
	newImageLoadHistory = NULL;
	status = STATUS_SUCCESS;

	if (ImageFilter::destroying)
	{
		return;
	}

	// Check IRQL level - if above PASSIVE_LEVEL, queue a DPC for later processing
	if (KeGetCurrentIrql() > PASSIVE_LEVEL) {
		DBGPRINT("ImageFilter!LoadImageNotifyRoutine: Deferring processing due to high IRQL (%d)", KeGetCurrentIrql());
		
		// Store parameters for deferred processing
		DeferredImageName = FullImageName;
		DeferredProcessId = ProcessId;
		DeferredImageInfo = ImageInfo;
		
		// Queue the DPC to run later at PASSIVE_LEVEL
		KeInsertQueueDpc(&ImageNotificationDpc, NULL, NULL);
		return;
	}

	//
	// Acquire a shared lock to iterate processes.
	//
	AcquireProcessLock();

	//
	// Iterate histories for a match.
	//
	if (ImageFilter::ProcessHistory)
	{
		// Iterate through the array
		for (ULONG64 i = 0; i < ImageFilter::ProcessHistorySize; i++) {
			if (ImageFilter::ProcessHistory[i].ProcessId == ProcessId && ImageFilter::ProcessHistory[i].ProcessTerminated == FALSE)
			{
				currentProcessHistory = &ImageFilter::ProcessHistory[i];
				break;
			}
		}
	}

	//
	// This might happen if we load on a running machine that already has processes.
	//
	if (currentProcessHistory == NULL)
	{
		DBGPRINT("ImageFilter!LoadImageNotifyRoutine: Failed to find PID %p in history.", ProcessId);
		status = STATUS_NOT_FOUND;
		goto Exit;
	}

	//
	// Allocate space for the new image history entry - use NON_PAGED pool for high IRQL scenarios
	//
	newImageLoadHistory = RCAST<PIMAGE_LOAD_HISTORY_ENTRY>(ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(IMAGE_LOAD_HISTORY_ENTRY), IMAGE_HISTORY_TAG));
	if (newImageLoadHistory == NULL)
	{
		DBGPRINT("ImageFilter!LoadImageNotifyRoutine: Failed to allocate space for the image history entry.");
		status = STATUS_NO_MEMORY;
		goto Exit;
	}
	memset(newImageLoadHistory, 0, sizeof(IMAGE_LOAD_HISTORY_ENTRY));

	newImageLoadHistory->CallerProcessId = PsGetCurrentProcessId();
	if (PsGetCurrentProcessId() != ProcessId)
	{
		newImageLoadHistory->RemoteImage = TRUE;
		ImageFilter::GetProcessImageFileName(PsGetCurrentProcessId(), &newImageLoadHistory->CallerImageFileName);
	}

	//
	// Copy the image file name if it is provided.
	//
	if (FullImageName)
	{
		//
		// Allocate the copy buffer using NON_PAGED pool for high IRQL compatibility
		//
		newImageLoadHistory->ImageFileName.Buffer = RCAST<PWCH>(ExAllocatePool2(POOL_FLAG_NON_PAGED, SCAST<SIZE_T>(FullImageName->Length) + 2, IMAGE_NAME_TAG));
		if (newImageLoadHistory->ImageFileName.Buffer == NULL)
		{
			DBGPRINT("ImageFilter!LoadImageNotifyRoutine: Failed to allocate space for the image file name.");
			status = STATUS_NO_MEMORY;
			goto Exit;
		}

		newImageLoadHistory->ImageFileName.Length = SCAST<SIZE_T>(FullImageName->Length) + 2;
		newImageLoadHistory->ImageFileName.MaximumLength = SCAST<SIZE_T>(FullImageName->Length) + 2;

		//
		// Copy the image name.
		//
		status = RtlStringCbCopyUnicodeString(newImageLoadHistory->ImageFileName.Buffer, SCAST<SIZE_T>(FullImageName->Length) + 2, FullImageName);
		if (NT_SUCCESS(status) == FALSE)
		{
			DBGPRINT("ImageFilter!LoadImageNotifyRoutine: Failed to copy the image file name with status 0x%X. Destination size = 0x%X, Source Size = 0x%X.",
				status,
				(unsigned int)(SCAST<SIZE_T>(FullImageName->Length) + 2),
				(unsigned int)(SCAST<SIZE_T>(FullImageName->Length)));

			goto Exit;
		}
	}

	//
	// Grab the user-mode stack.
	//
	newImageLoadHistory->CallerStackHistorySize = MAX_STACK_RETURN_HISTORY; // Will be updated in the resolve function.
	walker.WalkAndResolveStack(&newImageLoadHistory->CallerStackHistory, &newImageLoadHistory->CallerStackHistorySize, STACK_HISTORY_TAG);
	// Don't fail if we can't get stack info, just continue without it
	if (newImageLoadHistory->CallerStackHistory == NULL)
	{
		DBGPRINT("ImageFilter!LoadImageNotifyRoutine: Failed to allocate space for the stack history - continuing without stack info.");
		newImageLoadHistory->CallerStackHistorySize = 0;
	}

	// Use process lock instead for simplicity
	AcquireProcessLock();

	InsertHeadList(RCAST<PLIST_ENTRY>(currentProcessHistory->ImageLoadHistory), RCAST<PLIST_ENTRY>(newImageLoadHistory));
	currentProcessHistory->ImageLoadHistorySize++;

	// Release process lock
	ReleaseProcessLock();

	//
	// Audit the stack.
	//
	if (newImageLoadHistory->CallerStackHistory != NULL && newImageLoadHistory->CallerStackHistorySize > 0) {
		ImageFilter::detector->AuditUserStackWalk(ImageLoad,
			PsGetCurrentProcessId(),
			currentProcessHistory->ProcessImageFileName,
			&newImageLoadHistory->ImageFileName,
			newImageLoadHistory->CallerStackHistory,
			newImageLoadHistory->CallerStackHistorySize);
	}
Exit:
	//
	// Release the lock.
	//
	ReleaseProcessLock();

	//
	// Clean up on failure.
	//
	if (newImageLoadHistory && NT_SUCCESS(status) == FALSE)
	{
		if (newImageLoadHistory->ImageFileName.Buffer)
		{
			ExFreePoolWithTag(newImageLoadHistory->ImageFileName.Buffer, IMAGE_NAME_TAG);
			DBGPRINT("Free'd 'PmIn' at %p.", newImageLoadHistory->ImageFileName.Buffer);
		}
		if (newImageLoadHistory->CallerStackHistory)
		{
			ExFreePoolWithTag(newImageLoadHistory->CallerStackHistory, STACK_HISTORY_TAG);
			DBGPRINT("Free'd 'PmSh' at %p.", newImageLoadHistory->CallerStackHistory);
		}
		ExFreePoolWithTag(newImageLoadHistory, IMAGE_HISTORY_TAG);
		DBGPRINT("Free'd 'PmIh' at %p.", newImageLoadHistory);
	}
}
