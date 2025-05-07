// Copy this fixed function to resolve the C6101 warning

/**
 * Get image load history for a specific process or all processes
 * @param ProcessId - The process ID to get image load history for (0 for all processes)
 * @param ImageLoadInfoArray - Array to fill with image load information
 * @param MaxEntries - Maximum number of entries to retrieve
 * @return Number of entries retrieved
 */
ULONG
ImageFilter::GetImageLoadHistory(
	_In_ HANDLE ProcessId,
	_Out_ PIMAGE_LOAD_INFO ImageLoadInfoArray,
	_In_ ULONG MaxEntries)
{
	// Initialize variables
	PROCESS_HISTORY_ENTRY currentProcessHistory = {0}; // Initialize to zero
	PIMAGE_LOAD_HISTORY_ENTRY currentImageEntry = NULL;
	ULONG entryCount = 0;

	// IMPORTANT: Always initialize output array FIRST to fix warning C6101
	// This ensures the array is initialized even if we return early
	if (ImageLoadInfoArray != NULL && MaxEntries > 0) {
		RtlZeroMemory(ImageLoadInfoArray, MaxEntries * sizeof(IMAGE_LOAD_INFO));
	}
	
	// Early exit if parameters aren't valid - array is already initialized
	if (ImageFilter::destroying || MaxEntries == 0 || ImageLoadInfoArray == NULL)
	{
		return 0;
	}

	// Continue with the rest of the original function...
	// (The existing function body after this point is fine with the above changes)
}
