/**
	Increment process thread count by one and retrieve the latest value.
	@param ProcessId - The process ID of the target process.
	@param ThreadCount - The resulting thread count.
	@return Whether or not the process was found.
*/
BOOLEAN
ImageFilter::AddProcessThreadCount(
	_In_ HANDLE ProcessId,
	_Inout_ ULONG *ThreadCount)
{
	PPROCESS_HISTORY_ENTRY currentProcessHistory;
	BOOLEAN foundProcess;

	foundProcess = FALSE;

	// Initialize the output value to ensure it's never uninitialized
	if (ThreadCount != NULL) {
		*ThreadCount = 0;
	}

	if (ImageFilter::destroying)
	{
		return foundProcess;
	}

	// Check IRQL - we shouldn't do this at high IRQLs
	if (KeGetCurrentIrql() > PASSIVE_LEVEL) {
		DBGPRINT("ImageFilter!AddProcessThreadCount: Skipping due to high IRQL (%d)", KeGetCurrentIrql());
		return FALSE; // Skip at high IRQL
	}

	//
	// Acquire a shared lock to iterate processes.
	//
	AcquireProcessLock();

	if (ImageFilter::ProcessHistory)
	{
		// Iterate through the array
		for (ULONG64 i = 0; i < ImageFilter::ProcessHistorySize; i++) {
			currentProcessHistory = &ImageFilter::ProcessHistory[i];
			if (ProcessId == currentProcessHistory->ProcessId &&
				currentProcessHistory->ProcessTerminated == FALSE)
			{
				currentProcessHistory->ProcessThreadCount++;
				if (ThreadCount != NULL) {
					*ThreadCount = currentProcessHistory->ProcessThreadCount;
				}
				foundProcess = TRUE;
				break;
			}
			// Already advancing in the for loop
		}
	}

	//
	// Release the lock.
	//
	ReleaseProcessLock();

	return foundProcess;
}
