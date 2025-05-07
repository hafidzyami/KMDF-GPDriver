/**
	Register the necessary notify routines with improved DPC initialization.
	@param Detector - Detection instance used to analyze untrusted operations.
	@param InitializeStatus - Status of initialization.
*/
ImageFilter::ImageFilter(
	_In_ PDETECTION_LOGIC Detector,
	_Out_ NTSTATUS *InitializeStatus)
{
	NTSTATUS tempStatus = STATUS_SUCCESS;

	//
	// Initialize process history components
	//

	//
	// Set the create process notify routine.
	//
	tempStatus = PsSetCreateProcessNotifyRoutineEx(ImageFilter::CreateProcessNotifyRoutine, FALSE);
	if (NT_SUCCESS(tempStatus) == FALSE)
	{
		DBGPRINT("ImageFilter!ImageFilter: Failed to register create process notify routine with status 0x%X.", tempStatus);
		*InitializeStatus = tempStatus;
		return;
	}

	//
	// Set the load image notify routine.
	//
	tempStatus = PsSetLoadImageNotifyRoutine(ImageFilter::LoadImageNotifyRoutine);
	if (NT_SUCCESS(tempStatus) == FALSE)
	{
		DBGPRINT("ImageFilter!ImageFilter: Failed to register load image notify routine with status 0x%X.", tempStatus);
		*InitializeStatus = tempStatus;
		return;
	}

	// Initialize spin lock
	KeInitializeSpinLock(&ImageFilter::ProcessHistoryLock);

	// Allocate array-based process history instead of linked list - use NON_PAGED pool
	ImageFilter::ProcessHistory = RCAST<PPROCESS_HISTORY_ENTRY>(ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(PROCESS_HISTORY_ENTRY) * 100, PROCESS_HISTORY_TAG));
	if (ImageFilter::ProcessHistory == NULL)
	{
		DBGPRINT("ImageFilter!ImageFilter: Failed to allocate the process history array.");
		*InitializeStatus = STATUS_NO_MEMORY;
		return;
	}
	memset(ImageFilter::ProcessHistory, 0, sizeof(PROCESS_HISTORY_ENTRY) * 100);
	// Initialize the array entries
	for (int i = 0; i < 100; i++)
	{
		InitializeListHead(&ImageFilter::ProcessHistory[i].ListEntry);
	}
	this->ProcessHistorySize = 0;

	//
	// Set the detector.
	//
	ImageFilter::detector = Detector;

	//
	// Initialize thread filter components
	//

	//
	// Create a thread notify routine.
	//
	tempStatus = PsSetCreateThreadNotifyRoutine(ImageFilter::ThreadNotifyRoutine);
	if (NT_SUCCESS(tempStatus) == FALSE)
	{
		DBGPRINT("ImageFilter!ImageFilter: Failed to create thread notify routine with status 0x%X.", tempStatus);
		*InitializeStatus = tempStatus;
		return;
	}

	// Initialize DPC for deferred image processing
	if (!DpcInitialized) {
		KeInitializeDpc(&ImageNotificationDpc, DeferredImageNotifyRoutine, NULL);
		DpcInitialized = TRUE;
	}

	*InitializeStatus = STATUS_SUCCESS;
}
