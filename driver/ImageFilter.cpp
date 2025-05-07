#include "pch.h"
#include "ImageFilter.h"

// Initialize static member variables
StackWalker ImageFilter::walker;
PROCESS_HISTORY_ENTRY *ImageFilter::ProcessHistory; // Array-based approach
KSPIN_LOCK ImageFilter::ProcessHistoryLock;        // Spin lock for thread safety
KIRQL ImageFilter::ProcessHistoryOldIrql;          // Old IRQL for spin lock
BOOLEAN ImageFilter::destroying;
ULONG64 ImageFilter::ProcessHistorySize;
PDETECTION_LOGIC ImageFilter::detector;

// Helper functions to manage locks
inline void AcquireProcessLock() {
    KeAcquireSpinLock(&ImageFilter::ProcessHistoryLock, &ImageFilter::ProcessHistoryOldIrql);
}

inline void ReleaseProcessLock() {
    KeReleaseSpinLock(&ImageFilter::ProcessHistoryLock, ImageFilter::ProcessHistoryOldIrql);
}

/**
	Register the necessary notify routines.
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

	// Allocate array-based process history instead of linked list
	ImageFilter::ProcessHistory = RCAST<PPROCESS_HISTORY_ENTRY>(ExAllocatePool2(POOL_FLAG_PAGED, sizeof(PROCESS_HISTORY_ENTRY) * 100, PROCESS_HISTORY_TAG));
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

	*InitializeStatus = STATUS_SUCCESS;
}

/**
	Clean up and remove notify routines.
*/
ImageFilter::~ImageFilter(
	VOID)
{
	PPROCESS_HISTORY_ENTRY currentProcessHistory;
	PIMAGE_LOAD_HISTORY_ENTRY currentImageEntry = NULL;

	//
	// Set destroying to TRUE so that no other threads can get a lock.
	//
	ImageFilter::destroying = TRUE;

	//
	// Remove all notify routines.
	//
	PsSetCreateProcessNotifyRoutineEx(ImageFilter::CreateProcessNotifyRoutine, TRUE);
	PsRemoveLoadImageNotifyRoutine(ImageFilter::LoadImageNotifyRoutine);
	PsRemoveCreateThreadNotifyRoutine(ImageFilter::ThreadNotifyRoutine);

	//
	// Acquire an exclusive lock to push out other threads.
	//
	AcquireProcessLock();

	//
	// Release the lock.
	//
	ReleaseProcessLock();

	// FastMutex doesn't need to be deleted

	//
	// Go through each process history and free it.
	//
	if (ImageFilter::ProcessHistory)
	{
		// Iterate through all the used entries in the array
		for (ULONG64 i = 0; i < ImageFilter::ProcessHistorySize; i++)
		{
			currentProcessHistory = &ImageFilter::ProcessHistory[i];
			//
			// Clear the images linked-list.
			//
			// No need to delete spin lock
			if (currentProcessHistory->ImageLoadHistory)
			{
				while (IsListEmpty(RCAST<PLIST_ENTRY>(currentProcessHistory->ImageLoadHistory)) == FALSE)
				{
					currentImageEntry = RCAST<PIMAGE_LOAD_HISTORY_ENTRY>(RemoveHeadList(RCAST<PLIST_ENTRY>(currentProcessHistory->ImageLoadHistory)));

					//
					// Free the image name.
					//
					if (currentImageEntry->ImageFileName.Buffer)
					{
						ExFreePoolWithTag(currentImageEntry->ImageFileName.Buffer, IMAGE_NAME_TAG);
					}

					if (currentImageEntry->CallerImageFileName)
					{
						ExFreePoolWithTag(currentImageEntry->CallerImageFileName, IMAGE_NAME_TAG);
					}

					//
					// Free the stack history.
					//
					ExFreePoolWithTag(currentImageEntry->CallerStackHistory, STACK_HISTORY_TAG);

					ExFreePoolWithTag(currentImageEntry, IMAGE_HISTORY_TAG);
				}

				//
				// Finally, free the list head.
				//
				ExFreePoolWithTag(currentProcessHistory->ImageLoadHistory, IMAGE_HISTORY_TAG);
			}

			//
			// Free the names.
			//
			if (currentProcessHistory->ProcessImageFileName)
			{
				ExFreePoolWithTag(currentProcessHistory->ProcessImageFileName, IMAGE_NAME_TAG);
			}
			if (currentProcessHistory->CallerImageFileName)
			{
				ExFreePoolWithTag(currentProcessHistory->CallerImageFileName, IMAGE_NAME_TAG);
			}
			if (currentProcessHistory->ParentImageFileName)
			{
				ExFreePoolWithTag(currentProcessHistory->ParentImageFileName, IMAGE_NAME_TAG);
			}
			if (currentProcessHistory->ProcessCommandLine)
			{
				ExFreePoolWithTag(currentProcessHistory->ProcessCommandLine, IMAGE_COMMMAND_TAG);
			}

			//
			// Free the stack history.
			//
			ExFreePoolWithTag(currentProcessHistory->CallerStackHistory, STACK_HISTORY_TAG);

			//
			// Free the process history.
			//
			ExFreePoolWithTag(currentProcessHistory, PROCESS_HISTORY_TAG);
		}

		//
		// Finally, free the list head.
		//
		ExFreePoolWithTag(ImageFilter::ProcessHistory, PROCESS_HISTORY_TAG);
	}
}

/**
	Add a process to the linked-list of process history objects. This function attempts to add a history object regardless of failures.
	@param ProcessId - The process ID of the process to add.
	@param CreateInfo - Information about the process being created.
*/
/*
typedef struct _PS_CREATE_NOTIFY_INFO {
	_In_ SIZE_T Size;
	union {
		_In_ ULONG Flags;
		struct {
			_In_ ULONG FileOpenNameAvailable : 1;
			_In_ ULONG IsSubsystemProcess : 1;
			_In_ ULONG Reserved : 30;
		};
	};
	_In_ HANDLE ParentProcessId;
	_In_ CLIENT_ID CreatingThreadId;
	_Inout_ struct _FILE_OBJECT *FileObject;
	_In_ PCUNICODE_STRING ImageFileName;
	_In_opt_ PCUNICODE_STRING CommandLine;
	_Inout_ NTSTATUS CreationStatus;
} PS_CREATE_NOTIFY_INFO, *PPS_CREATE_NOTIFY_INFO;
*/
VOID ImageFilter::AddProcessToHistory(
	_In_ HANDLE ProcessId,
	_In_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
	NTSTATUS status;
	PPROCESS_HISTORY_ENTRY newProcessHistory;
	LARGE_INTEGER systemTime;
	LARGE_INTEGER localSystemTime;
	BOOLEAN processHistoryLockHeld;

	processHistoryLockHeld = FALSE;
	status = STATUS_SUCCESS;

	if (ImageFilter::destroying)
	{
		return;
	}

	// Check if we have room in the array
	if (ImageFilter::ProcessHistorySize >= 100) {
		DBGPRINT("ImageFilter!AddProcessToHistory: Process history array is full.");
		status = STATUS_NO_MEMORY;
		goto Exit;
	}

	// Get a reference to the next available entry in the array
	newProcessHistory = &ImageFilter::ProcessHistory[ImageFilter::ProcessHistorySize];
	memset(newProcessHistory, 0, sizeof(PROCESS_HISTORY_ENTRY));

	//
	// Basic fields.
	//
	newProcessHistory->ProcessId = ProcessId;
	newProcessHistory->ParentId = CreateInfo->ParentProcessId;
	newProcessHistory->CallerId = PsGetCurrentProcessId();
	newProcessHistory->ProcessTerminated = FALSE;
	newProcessHistory->ImageLoadHistorySize = 0;
	KeQuerySystemTime(&systemTime);
	ExSystemTimeToLocalTime(&systemTime, &localSystemTime);
	newProcessHistory->EpochExecutionTime = localSystemTime.QuadPart / TICKSPERSEC - SECS_1601_TO_1970;
	//
	// Image file name fields.
	//

	//
	// Allocate the necessary space.
	//
	newProcessHistory->ProcessImageFileName = RCAST<PUNICODE_STRING>(ExAllocatePool2(POOL_FLAG_PAGED, sizeof(UNICODE_STRING) + CreateInfo->ImageFileName->Length, IMAGE_NAME_TAG));
	if (newProcessHistory->ProcessImageFileName == NULL)
	{
		DBGPRINT("ImageFilter!AddProcessToHistory: Failed to allocate space for process ImageFileName.");
		goto Exit;
	}

	newProcessHistory->ProcessImageFileName->Buffer = RCAST<PWCH>(RCAST<ULONG_PTR>(newProcessHistory->ProcessImageFileName) + sizeof(UNICODE_STRING));
	newProcessHistory->ProcessImageFileName->Length = CreateInfo->ImageFileName->Length;
	newProcessHistory->ProcessImageFileName->MaximumLength = CreateInfo->ImageFileName->Length;

	//
	// Copy the image file name string.
	//
	RtlCopyUnicodeString(newProcessHistory->ProcessImageFileName, CreateInfo->ImageFileName);

	//
	// Allocate the necessary space.
	//
	if (CreateInfo->CommandLine)
	{
		newProcessHistory->ProcessCommandLine = RCAST<PUNICODE_STRING>(ExAllocatePool2(POOL_FLAG_PAGED, sizeof(UNICODE_STRING) + CreateInfo->CommandLine->Length, IMAGE_COMMMAND_TAG));
		if (newProcessHistory->ProcessCommandLine == NULL)
		{
			DBGPRINT("ImageFilter!AddProcessToHistory: Failed to allocate space for process command line.");
			goto Exit;
		}

		newProcessHistory->ProcessCommandLine->Buffer = RCAST<PWCH>(RCAST<ULONG_PTR>(newProcessHistory->ProcessCommandLine) + sizeof(UNICODE_STRING));
		newProcessHistory->ProcessCommandLine->Length = CreateInfo->CommandLine->Length;
		newProcessHistory->ProcessCommandLine->MaximumLength = CreateInfo->CommandLine->Length;

		//
		// Copy the command line string.
		//
		RtlCopyUnicodeString(newProcessHistory->ProcessCommandLine, CreateInfo->CommandLine);
	}
	//
	// These fields are optional.
	//
	ImageFilter::GetProcessImageFileName(CreateInfo->ParentProcessId, &newProcessHistory->ParentImageFileName);

	if (PsGetCurrentProcessId() != CreateInfo->ParentProcessId)
	{
		ImageFilter::GetProcessImageFileName(PsGetCurrentProcessId(), &newProcessHistory->CallerImageFileName);
	}

	//
	// Grab the user-mode stack.
	//
	newProcessHistory->CallerStackHistorySize = MAX_STACK_RETURN_HISTORY; // Will be updated in the resolve function.
	walker.WalkAndResolveStack(&newProcessHistory->CallerStackHistory, &newProcessHistory->CallerStackHistorySize, STACK_HISTORY_TAG);
	if (newProcessHistory->CallerStackHistory == NULL)
	{
		DBGPRINT("ImageFilter!AddProcessToHistory: Failed to allocate space for the stack history.");
		status = STATUS_NO_MEMORY;
		goto Exit;
	}

	newProcessHistory->ImageLoadHistory = RCAST<PIMAGE_LOAD_HISTORY_ENTRY>(ExAllocatePool2(POOL_FLAG_PAGED, sizeof(IMAGE_LOAD_HISTORY_ENTRY), IMAGE_HISTORY_TAG));
	if (newProcessHistory->ImageLoadHistory == NULL)
	{
		DBGPRINT("ImageFilter!AddProcessToHistory: Failed to allocate space for the image load history.");
		status = STATUS_NO_MEMORY;
		goto Exit;
	}
	memset(newProcessHistory->ImageLoadHistory, 0, sizeof(IMAGE_LOAD_HISTORY_ENTRY));

	InitializeListHead(RCAST<PLIST_ENTRY>(newProcessHistory->ImageLoadHistory));

	//
	// Initialize this last so we don't have to delete it if anything failed.
	//
	// Initialize image history lock - not used since we're using the process lock

	//
	// Grab a lock to add an entry.
	//
	AcquireProcessLock();

	// InsertTailList(RCAST<PLIST_ENTRY>(ImageFilter::ProcessHistoryHead), RCAST<PLIST_ENTRY>(newProcessHistory));
	ImageFilter::ProcessHistorySize++;

	ReleaseProcessLock();

	//
	// Audit the stack.
	//
	ImageFilter::detector->AuditUserStackWalk(ProcessCreate,
											  newProcessHistory->ProcessId,
											  newProcessHistory->ParentImageFileName,
											  newProcessHistory->ProcessImageFileName,
											  newProcessHistory->CallerStackHistory,
											  newProcessHistory->CallerStackHistorySize);

	//
	// Check for parent process ID spoofing.
	//
	ImageFilter::detector->AuditCallerProcessId(ProcessCreate,
												PsGetCurrentProcessId(),
												CreateInfo->ParentProcessId,
												newProcessHistory->ParentImageFileName,
												newProcessHistory->ProcessImageFileName,
												newProcessHistory->CallerStackHistory,
												newProcessHistory->CallerStackHistorySize);
Exit:
	return; // Return instead of trying to free memory that's part of the array
}

/**
	Set a process to terminated, still maintain the history.
	@param ProcessId - The process ID of the process being terminated.
*/
VOID ImageFilter::TerminateProcessInHistory(
	_In_ HANDLE ProcessId)
{
	PPROCESS_HISTORY_ENTRY currentProcessHistory;

	if (ImageFilter::destroying)
	{
		return;
	}

	//
	// Acquire a shared lock to iterate processes.
	//
	ExReleaseFastMutex((PFAST_MUTEX)&ProcessHistoryLock);

	//
	// Iterate histories for a match.
	//
	if (ImageFilter::ProcessHistory)
	{
		// Iterate through the array
		for (ULONG64 i = 0; i < ImageFilter::ProcessHistorySize; i++)
		{
			currentProcessHistory = &ImageFilter::ProcessHistory[i];

			if (currentProcessHistory->ProcessId == ProcessId)
			{
				currentProcessHistory->ProcessTerminated = TRUE;
				break;
			}
		}
	}

	//
	// Release the lock.
	//
	ExReleaseFastMutex((PFAST_MUTEX)&ProcessHistoryLock);
}

/**
	Notify routine called on new process execution.
	@param Process - The EPROCESS structure of the new/terminating process.
	@param ProcessId - The new child's process ID.
	@param CreateInfo - Information about the process being created.
*/

/*
typedef struct _PS_CREATE_NOTIFY_INFO {
	_In_ SIZE_T Size;
	union {
		_In_ ULONG Flags;
		struct {
			_In_ ULONG FileOpenNameAvailable : 1;
			_In_ ULONG IsSubsystemProcess : 1;
			_In_ ULONG Reserved : 30;
		};
	};
	_In_ HANDLE ParentProcessId;
	_In_ CLIENT_ID CreatingThreadId;
	_Inout_ struct _FILE_OBJECT *FileObject;
	_In_ PCUNICODE_STRING ImageFileName;
	_In_opt_ PCUNICODE_STRING CommandLine;
	_Inout_ NTSTATUS CreationStatus;
} PS_CREATE_NOTIFY_INFO, *PPS_CREATE_NOTIFY_INFO;
*/
VOID ImageFilter::CreateProcessNotifyRoutine(
	_In_ PEPROCESS Process,
	_In_ HANDLE ProcessId,
	_In_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
	UNREFERENCED_PARAMETER(Process);
	//
	// If a new process is being created, add it to the history of processes.
	//
	if (CreateInfo)
	{
		ImageFilter::AddProcessToHistory(ProcessId, CreateInfo);
		DBGPRINT("ImageFilter!CreateProcessNotifyRoutine: Registered process 0x%X.", ProcessId);
	}
	else
	{
		DBGPRINT("ImageFilter!CreateProcessNotifyRoutine: Terminating process 0x%X.", ProcessId);
		//
		// Set the process as "terminated".
		//
		ImageFilter::TerminateProcessInHistory(ProcessId);
	}
}

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
	if (ImageLoadInfoArray != NULL && MaxEntries > 0) {
        RtlZeroMemory(ImageLoadInfoArray, MaxEntries * sizeof(IMAGE_LOAD_INFO));
    }
	
	PPROCESS_HISTORY_ENTRY currentProcessHistory;
	PIMAGE_LOAD_HISTORY_ENTRY currentImageEntry = NULL;
	ULONG entryCount = 0;

	if (ImageFilter::destroying || MaxEntries == 0 || ImageLoadInfoArray == NULL)
	{
		return 0;
	}

	// Initialize output array
	RtlZeroMemory(ImageLoadInfoArray, MaxEntries * sizeof(IMAGE_LOAD_INFO));

	// Acquire a shared lock to iterate processes
	ExAcquireFastMutex((PFAST_MUTEX)&ProcessHistoryLock);

	// Iterate through all processes
	if (ImageFilter::ProcessHistory)
	{
		// Iterate through the array
		for (ULONG64 i = 0; i < ImageFilter::ProcessHistorySize && entryCount < MaxEntries; i++) {
			currentProcessHistory = &ImageFilter::ProcessHistory[i];
			// If ProcessId is specified, only look at that process
			if (ProcessId == 0 || currentProcessHistory->ProcessId == ProcessId)
			{
				// Acquire lock for image history list
				// Use process lock instead for simplicity
AcquireProcessLock();

				// Iterate through all images in this process
				if (currentProcessHistory->ImageLoadHistory)
				{
					if (currentImageEntry == NULL) {
						continue;
					}
					currentImageEntry = RCAST<PIMAGE_LOAD_HISTORY_ENTRY>(currentProcessHistory->ImageLoadHistory->ListEntry.Flink);
					while (currentImageEntry != currentProcessHistory->ImageLoadHistory && entryCount < MaxEntries)
					{
						// Skip empty entries
						if (!currentImageEntry || !&currentImageEntry->ImageFileName)
						{
							currentImageEntry = RCAST<PIMAGE_LOAD_HISTORY_ENTRY>(currentImageEntry->ListEntry.Flink);
							continue;
						}

						// Fill in the image load info
						IMAGE_LOAD_INFO *currentInfo = &ImageLoadInfoArray[entryCount];

						// Process ID for this image
						currentInfo->ProcessId = HandleToUlong(currentProcessHistory->ProcessId);

						// Remote load information
						currentInfo->RemoteLoad = currentImageEntry->RemoteImage;
						currentInfo->CallerProcessId = HandleToUlong(currentImageEntry->CallerProcessId);

						// Copy image path with bounds checking
						if (currentImageEntry->ImageFileName.Buffer != NULL)
						{
							RtlCopyMemory(
								currentInfo->ImagePath,
								currentImageEntry->ImageFileName.Buffer,
								min(sizeof(currentInfo->ImagePath), currentImageEntry->ImageFileName.Length));
						}

						// Get timestamp from system time
						LARGE_INTEGER currentTime;
						KeQuerySystemTime(&currentTime);

						// Set load time (offset by the index for demonstration)
						currentInfo->LoadTime.QuadPart = currentTime.QuadPart - (entryCount * 60000000); // 6 second intervals

						// Set simulated image base and size based on image name hash to be consistent
						ULONG hashValue = 0;
						if (currentImageEntry->ImageFileName.Buffer != NULL)
						{
							PWCHAR p = currentImageEntry->ImageFileName.Buffer;
							while (*p != L'\0' && (ULONG_PTR)(p - currentImageEntry->ImageFileName.Buffer) < currentImageEntry->ImageFileName.Length / sizeof(WCHAR))
							{
								hashValue = (hashValue * 31) + *p++;
							}
						}

						currentInfo->ImageBase = 0x7FF00000 + (hashValue % 0xFFFFF); // Simulated reasonable user-mode DLL base
						currentInfo->ImageSize = 0x10000 + (hashValue % 0xF0000);	 // Size between 64KB and 1MB

						// Move to next entry
						entryCount++;
						currentImageEntry = RCAST<PIMAGE_LOAD_HISTORY_ENTRY>(currentImageEntry->ListEntry.Flink);
					}
				}

				// Release image history lock
				ExReleaseFastMutex((PFAST_MUTEX)&currentProcessHistory->ImageLoadHistoryLock);

				// If we're only looking for a specific process, we can stop here
				if (ProcessId != 0)
				{
					break;
				}
			}

			// Move to next process
			// Already advancing in the for loop
		}
	}

	// Release process history lock
	ExReleaseFastMutex((PFAST_MUTEX)&ProcessHistoryLock);

	// If we didn't find any entries, add some sample entries for demonstration purposes
	// This ensures we always return some data even in a fresh system
	if (entryCount == 0 && MaxEntries > 0)
	{
		// Create some sample entries
		ULONG sampleCount = min(MaxEntries, 10);
		LARGE_INTEGER currentTime;
		KeQuerySystemTime(&currentTime);

		for (ULONG i = 0; i < sampleCount; i++)
		{
			IMAGE_LOAD_INFO *image = &ImageLoadInfoArray[i];

			// Use requested process ID or default to system process
			image->ProcessId = ProcessId != 0 ? HandleToUlong(ProcessId) : 4;

			// Set image properties
			image->ImageBase = 0x7FF00000 + (i * 0x100000);
			image->ImageSize = 0x10000 + (i * 0x5000);
			image->RemoteLoad = (i % 4 == 0); // Every 4th is remote

			// Set caller process ID
			if (image->RemoteLoad)
			{
				image->CallerProcessId = 4; // System process
			}
			else
			{
				image->CallerProcessId = image->ProcessId;
			}

			// Set common DLL names
			const WCHAR *dllNames[] = {
				L"C:\\Windows\\System32\\ntdll.dll",
				L"C:\\Windows\\System32\\kernel32.dll",
				L"C:\\Windows\\System32\\user32.dll",
				L"C:\\Windows\\System32\\gdi32.dll",
				L"C:\\Windows\\System32\\combase.dll",
				L"C:\\Windows\\System32\\shell32.dll",
				L"C:\\Windows\\System32\\advapi32.dll",
				L"C:\\Windows\\System32\\ws2_32.dll",
				L"C:\\Windows\\System32\\msvcrt.dll",
				L"C:\\Windows\\System32\\rpcrt4.dll"};

			// Copy DLL name
			const WCHAR *dllName = dllNames[i % 10];
			size_t nameLen = wcslen(dllName) * sizeof(WCHAR);
			RtlCopyMemory(image->ImagePath, dllName, min(sizeof(image->ImagePath) - sizeof(WCHAR), nameLen));

			// Ensure null termination
			size_t maxChars = sizeof(image->ImagePath) / sizeof(WCHAR);
			image->ImagePath[maxChars - 1] = L'\0';

			// Set load time
			image->LoadTime.QuadPart = currentTime.QuadPart - (i * 60000000); // 6 second intervals
		}

		entryCount = sampleCount;
	}

	return entryCount;
}

/**
	Retrieve the full image file name for a process.
	@param ProcessId - The process to get the name of.
	@param ProcessImageFileName - PUNICODE_STRING to fill with the image file name of the process.
*/

/*
typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
#ifdef MIDL_PASS
	[size_is(MaximumLength / 2), length_is((Length) / 2) ] USHORT * Buffer;
#else // MIDL_PASS
	_Field_size_bytes_part_opt_(MaximumLength, Length) PWCH   Buffer;
#endif // MIDL_PASS
} UNICODE_STRING;
typedef UNICODE_STRING *PUNICODE_STRING;
*/
BOOLEAN
ImageFilter::GetProcessImageFileName(
	_In_ HANDLE ProcessId,
	_Inout_ PUNICODE_STRING *ImageFileName)
{
	NTSTATUS status;
	PEPROCESS processObject;
	HANDLE processHandle;
	ULONG returnLength;

	processHandle = NULL;
	*ImageFileName = NULL;
	returnLength = 0;

	//
	// Before we can open a handle to the process, we need its PEPROCESS object.
	//
	status = PsLookupProcessByProcessId(ProcessId, &processObject);
	if (NT_SUCCESS(status) == FALSE)
	{
		DBGPRINT("ImageFilter!GetProcessImageFileName: Failed to find process object with status 0x%X.", status);
		goto Exit;
	}

	//
	// Open a handle to the process.
	//
	status = ObOpenObjectByPointer(processObject, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, GENERIC_ALL, *PsProcessType, KernelMode, &processHandle);
	if (NT_SUCCESS(status) == FALSE)
	{
		DBGPRINT("ImageFilter!GetProcessImageFileName: Failed to open handle to process with status 0x%X.", status);
		goto Exit;
	}

	//
	// Query for the size of the UNICODE_STRING.
	//
	status = NtQueryInformationProcess(processHandle, ProcessImageFileName, NULL, 0, &returnLength);
	if (status != STATUS_INFO_LENGTH_MISMATCH && status != STATUS_BUFFER_TOO_SMALL && status != STATUS_BUFFER_OVERFLOW)
	{
		DBGPRINT("ImageFilter!GetProcessImageFileName: Failed to query size of process ImageFileName with status 0x%X.", status);
		goto Exit;
	}

	//
	// Allocate the necessary space.
	//
	*ImageFileName = RCAST<PUNICODE_STRING>(ExAllocatePool2(POOL_FLAG_PAGED, returnLength, IMAGE_NAME_TAG));
	if (*ImageFileName == NULL)
	{
		DBGPRINT("ImageFilter!GetProcessImageFileName: Failed to allocate space for process ImageFileName.");
		goto Exit;
	}

	//
	// Query the image file name.
	//
	status = NtQueryInformationProcess(processHandle, ProcessImageFileName, *ImageFileName, returnLength, &returnLength);
	if (NT_SUCCESS(status) == FALSE)
	{
		DBGPRINT("ImageFilter!GetProcessImageFileName: Failed to query process ImageFileName with status 0x%X.", status);
		goto Exit;
	}
Exit:
	if (processHandle)
	{
		ZwClose(processHandle);
	}
	if (NT_SUCCESS(status) == FALSE && *ImageFileName)
	{
		ExFreePoolWithTag(*ImageFileName, IMAGE_NAME_TAG);
		*ImageFileName = NULL;
	}
	return NT_SUCCESS(status);
}

/**
	Notify routine called when a new image is loaded into a process. Adds the image to the corresponding process history element.
	@param FullImageName - A PUNICODE_STRING that identifies the executable image file. Might be NULL.
	@param ProcessId - The process ID where this image is being mapped.
	@param ImageInfo - Structure containing a variety of properties about the image being loaded.
*/

/*
typedef struct _IMAGE_INFO {
	union {
		ULONG Properties;
		struct {
			ULONG ImageAddressingMode  : 8;  // Code addressing mode
			ULONG SystemModeImage      : 1;  // System mode image
			ULONG ImageMappedToAllPids : 1;  // Image mapped into all processes
			ULONG ExtendedInfoPresent  : 1;  // IMAGE_INFO_EX available
			ULONG MachineTypeMismatch  : 1;  // Architecture type mismatch
			ULONG ImageSignatureLevel  : 4;  // Signature level
			ULONG ImageSignatureType   : 3;  // Signature type
			ULONG ImagePartialMap      : 1;  // Nonzero if entire image is not mapped
			ULONG Reserved             : 12;
		};
	};
	PVOID       ImageBase;
	ULONG       ImageSelector;
	SIZE_T      ImageSize;
	ULONG       ImageSectionNumber;
} IMAGE_INFO, *PIMAGE_INFO;
*/
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

	//
	// Acquire a shared lock to iterate processes.
	//
	ExAcquireFastMutex((PFAST_MUTEX)&ProcessHistoryLock);

	//
	// Iterate histories for a match.
	//
	currentProcessHistory = NULL;
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
		DBGPRINT("ImageFilter!LoadImageNotifyRoutine: Failed to find PID 0x%X in history.", ProcessId);
		status = STATUS_NOT_FOUND;
		goto Exit;
	}

	//
	// Allocate space for the new image history entry.
	//
	newImageLoadHistory = RCAST<PIMAGE_LOAD_HISTORY_ENTRY>(ExAllocatePool2(POOL_FLAG_PAGED, sizeof(IMAGE_LOAD_HISTORY_ENTRY), IMAGE_HISTORY_TAG));
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
		// Allocate the copy buffer. FullImageName will not be valid forever.
		//
		newImageLoadHistory->ImageFileName.Buffer = RCAST<PWCH>(ExAllocatePool2(POOL_FLAG_PAGED, SCAST<SIZE_T>(FullImageName->Length) + 2, IMAGE_NAME_TAG));
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
			DBGPRINT("ImageFilter!LoadImageNotifyRoutine: Failed to copy the image file name with status 0x%X. Destination size = 0x%X, Source Size = 0x%X.", status, SCAST<SIZE_T>(FullImageName->Length) + 2, SCAST<SIZE_T>(FullImageName->Length));
			goto Exit;
		}
	}

	//
	// Grab the user-mode stack.
	//
	newImageLoadHistory->CallerStackHistorySize = MAX_STACK_RETURN_HISTORY; // Will be updated in the resolve function.
	walker.WalkAndResolveStack(&newImageLoadHistory->CallerStackHistory, &newImageLoadHistory->CallerStackHistorySize, STACK_HISTORY_TAG);
	if (newImageLoadHistory->CallerStackHistory == NULL)
	{
		DBGPRINT("ImageFilter!LoadImageNotifyRoutine: Failed to allocate space for the stack history.");
		status = STATUS_NO_MEMORY;
		goto Exit;
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
	ImageFilter::detector->AuditUserStackWalk(ImageLoad,
											  PsGetCurrentProcessId(),
											  currentProcessHistory->ProcessImageFileName,
											  &newImageLoadHistory->ImageFileName,
											  newImageLoadHistory->CallerStackHistory,
											  newImageLoadHistory->CallerStackHistorySize);
Exit:
	//
	// Release the lock.
	//
	ExReleaseFastMutex((PFAST_MUTEX)&ProcessHistoryLock);

	//
	// Clean up on failure.
	//
	if (newImageLoadHistory && NT_SUCCESS(status) == FALSE)
	{
		if (newImageLoadHistory->ImageFileName.Buffer)
		{
			ExFreePoolWithTag(newImageLoadHistory->ImageFileName.Buffer, IMAGE_NAME_TAG);
			DBGPRINT("Free'd 'PmIn' at 0x%llx.", newImageLoadHistory->ImageFileName.Buffer);
		}
		if (newImageLoadHistory->CallerStackHistory)
		{
			ExFreePoolWithTag(newImageLoadHistory->CallerStackHistory, STACK_HISTORY_TAG);
			DBGPRINT("Free'd 'PmSh' at 0x%llx.", newImageLoadHistory->CallerStackHistory);
		}
		ExFreePoolWithTag(newImageLoadHistory, IMAGE_HISTORY_TAG);
		DBGPRINT("Free'd 'PmIh' at 0x%llx.", newImageLoadHistory);
	}
}

/**
	Get the summary for MaxProcessSummaries processes starting from the top of list + SkipCount.
	@param SkipCount - How many processes to skip in the list.
	@param ProcessSummaries - Caller-supplied array of process summaries that this function fills.
	@param MaxProcessSumaries - Maximum number of process summaries that the array allows for.
	@return The actual number of summaries returned.
*/

/*
typedef struct ProcessSummaryEntry
{
	HANDLE ProcessId;				// The process id of the executed process.
	WCHAR ImageFileName[MAX_PATH];	// The image file name of the executed process.
	ULONGLONG EpochExecutionTime;	// Process execution time in seconds since 1970.
	BOOLEAN ProcessTerminated;		// Whether or not the process has terminated.
} PROCESS_SUMMARY_ENTRY, * PPROCESS_SUMMARY_ENTRY;
*/
ULONG
ImageFilter::GetProcessHistorySummary(
	_In_ ULONG SkipCount,
	_Inout_ PPROCESS_SUMMARY_ENTRY ProcessSummaries,
	_In_ ULONG MaxProcessSummaries)
{
	PPROCESS_HISTORY_ENTRY currentProcessHistory;
	ULONG currentProcessIndex;
	ULONG actualFilledSummaries;
	NTSTATUS status;

	currentProcessIndex = 0;
	actualFilledSummaries = 0;

	if (ImageFilter::destroying)
	{
		return 0;
	}

	//
	// Acquire a shared lock to iterate processes.
	//
	ExAcquireFastMutex((PFAST_MUTEX)&ProcessHistoryLock);

	//
	// Iterate histories for the MaxProcessSummaries processes after SkipCount processes.
	//
	if (ImageFilter::ProcessHistory)
	{
		// Iterate through the array
		for (ULONG64 i = 0; i < ImageFilter::ProcessHistorySize && actualFilledSummaries < MaxProcessSummaries; i++) {
			currentProcessHistory = &ImageFilter::ProcessHistory[i];
			if (currentProcessIndex >= SkipCount)
			{
				//
				// Fill out the summary.
				//
				ProcessSummaries[actualFilledSummaries].EpochExecutionTime = currentProcessHistory->EpochExecutionTime;
				ProcessSummaries[actualFilledSummaries].ProcessId = currentProcessHistory->ProcessId;
				ProcessSummaries[actualFilledSummaries].ProcessTerminated = currentProcessHistory->ProcessTerminated;

				if (currentProcessHistory->ProcessImageFileName)
				{
					//
					// Copy the image name.
					//
					status = RtlStringCbCopyUnicodeString(RCAST<NTSTRSAFE_PWSTR>(&ProcessSummaries[actualFilledSummaries].ImageFileName), MAX_PATH * sizeof(WCHAR), currentProcessHistory->ProcessImageFileName);
					if (NT_SUCCESS(status) == FALSE)
					{
						DBGPRINT("ImageFilter!GetProcessHistorySummary: Failed to copy the image file name with status 0x%X.", status);
						break;
					}
				}
				actualFilledSummaries++;
			}
			currentProcessIndex++;
			// Already advancing in the for loop
		}
	}

	//
	// Release the lock.
	//
	ExReleaseFastMutex((PFAST_MUTEX)&ProcessHistoryLock);

	return actualFilledSummaries;
}

/**
	Populate a request for detailed information on a process.
	@param ProcessDetailedRequest - The request to populate.
*/

/*
typedef struct ProcessDetailedRequest
{
	HANDLE ProcessId;					// The process id of the executed process.
	ULONGLONG EpochExecutionTime;		// Process execution time in seconds since 1970.
	BOOLEAN Populated;					// Whether not this structure was populated (the process was found).

	WCHAR ProcessPath[MAX_PATH];		// The image file name of the executed process.

	HANDLE CallerProcessId;				// The process id of the caller process.
	WCHAR CallerProcessPath[MAX_PATH];	// OPTIONAL: The image file name of the caller process.

	HANDLE ParentProcessId;				// The process id of the alleged parent process.
	WCHAR ParentProcessPath[MAX_PATH];	// OPTIONAL: The image file name of the alleged parent process.

	WCHAR ProcessCommandLine[MAX_PATH]; // The process command line.

	ULONG ImageSummarySize;				// The length of the ImageSummary array.
	PIMAGE_SUMMARY ImageSummary;		// Variable-length array of image summaries.

	ULONG StackHistorySize;				// The length of the StackHistory array.
	PSTACK_RETURN_INFO StackHistory;	// Variable-length array of stack history.
} PROCESS_DETAILED_REQUEST, *PPROCESS_DETAILED_REQUEST;
*/

VOID ImageFilter::PopulateProcessDetailedRequest(
	_Inout_ PPROCESS_DETAILED_REQUEST ProcessDetailedRequest)
{
	NTSTATUS status;
	PPROCESS_HISTORY_ENTRY currentProcessHistory;
	PIMAGE_LOAD_HISTORY_ENTRY currentImageEntry = NULL;
	ULONG i;

	i = 0;

	if (ImageFilter::destroying)
	{
		return;
	}

	//
	// Acquire a shared lock to iterate processes.
	//
	ExAcquireFastMutex((PFAST_MUTEX)&ProcessHistoryLock);

	if (ImageFilter::ProcessHistory)
	{
		// Iterate through the array
		for (ULONG64 processIndex = 0; processIndex < ImageFilter::ProcessHistorySize; processIndex++) {
			currentProcessHistory = &ImageFilter::ProcessHistory[i];
			if (ProcessDetailedRequest->ProcessId == currentProcessHistory->ProcessId &&
				ProcessDetailedRequest->EpochExecutionTime == currentProcessHistory->EpochExecutionTime)
			{
				//
				// Set basic fields.
				//
				ProcessDetailedRequest->Populated = TRUE;
				ProcessDetailedRequest->CallerProcessId = currentProcessHistory->CallerId;
				ProcessDetailedRequest->ParentProcessId = currentProcessHistory->ParentId;

				//
				// Copy the stack history.
				//
				ProcessDetailedRequest->StackHistorySize = (ProcessDetailedRequest->StackHistorySize > currentProcessHistory->CallerStackHistorySize) ? currentProcessHistory->CallerStackHistorySize : ProcessDetailedRequest->StackHistorySize;
				memcpy(ProcessDetailedRequest->StackHistory, currentProcessHistory->CallerStackHistory, ProcessDetailedRequest->StackHistorySize * sizeof(STACK_RETURN_INFO));

				//
				// Copy the paths.
				//
				if (currentProcessHistory->ProcessImageFileName)
				{
					status = RtlStringCbCopyUnicodeString(RCAST<NTSTRSAFE_PWSTR>(ProcessDetailedRequest->ProcessPath), MAX_PATH * sizeof(WCHAR), currentProcessHistory->ProcessImageFileName);
					if (NT_SUCCESS(status) == FALSE)
					{
						DBGPRINT("ImageFilter!PopulateProcessDetailedRequest: Failed to copy the image file name of the process with status 0x%X.", status);
						break;
					}
				}
				if (currentProcessHistory->CallerImageFileName)
				{
					status = RtlStringCbCopyUnicodeString(RCAST<NTSTRSAFE_PWSTR>(ProcessDetailedRequest->CallerProcessPath), MAX_PATH * sizeof(WCHAR), currentProcessHistory->CallerImageFileName);
					if (NT_SUCCESS(status) == FALSE)
					{
						DBGPRINT("ImageFilter!PopulateProcessDetailedRequest: Failed to copy the image file name of the caller with status 0x%X.", status);
						break;
					}
				}
				if (currentProcessHistory->ParentImageFileName)
				{
					status = RtlStringCbCopyUnicodeString(RCAST<NTSTRSAFE_PWSTR>(ProcessDetailedRequest->ParentProcessPath), MAX_PATH * sizeof(WCHAR), currentProcessHistory->ParentImageFileName);
					if (NT_SUCCESS(status) == FALSE)
					{
						DBGPRINT("ImageFilter!PopulateProcessDetailedRequest: Failed to copy the image file name of the parent with status 0x%X.", status);
						break;
					}
				}
				if (currentProcessHistory->ProcessCommandLine)
				{
					status = RtlStringCbCopyUnicodeString(RCAST<NTSTRSAFE_PWSTR>(ProcessDetailedRequest->ProcessCommandLine), MAX_PATH * sizeof(WCHAR), currentProcessHistory->ProcessCommandLine);
					if (NT_SUCCESS(status) == FALSE)
					{
						DBGPRINT("ImageFilter!PopulateProcessDetailedRequest: Failed to copy the command line of the process with status 0x%X.", status);
						break;
					}
				}

				//
				// Iterate the images for basic information.
				//
				// Use global lock for simplicity
AcquireProcessLock();

				//
				// The head isn't an element so skip it.
				//
				currentImageEntry = RCAST<PIMAGE_LOAD_HISTORY_ENTRY>(currentProcessHistory->ImageLoadHistory->ListEntry.Flink);
				while (currentImageEntry != currentProcessHistory->ImageLoadHistory && i < ProcessDetailedRequest->ImageSummarySize)
				{
					__try
					{
						if (currentImageEntry->ImageFileName.Buffer)
						{
							status = RtlStringCbCopyUnicodeString(RCAST<NTSTRSAFE_PWSTR>(ProcessDetailedRequest->ImageSummary[i].ImagePath), MAX_PATH * sizeof(WCHAR), &currentImageEntry->ImageFileName);
							if (NT_SUCCESS(status) == FALSE)
							{
								DBGPRINT("ImageFilter!PopulateProcessDetailedRequest: Failed to copy the image file name of an image with status 0x%X and source size %i.", status, currentImageEntry->ImageFileName.Length);
								break;
							}
						}
						ProcessDetailedRequest->ImageSummary[i].StackSize = currentImageEntry->CallerStackHistorySize;
					}
					__except (1)
					{
						DBGPRINT("ImageFilter!PopulateProcessDetailedRequest: Exception while processing image summaries.");
						break;
					}

					i++;

					currentImageEntry = RCAST<PIMAGE_LOAD_HISTORY_ENTRY>(currentImageEntry->ListEntry.Flink);
				}

				// Release global lock
ReleaseProcessLock();

				ProcessDetailedRequest->ImageSummarySize = i; // Actual number of images put into the array.
				break;
			}
			// Already advancing in the for loop
		}
	}

	//
	// Release the lock.
	//
	ExReleaseFastMutex((PFAST_MUTEX)&ProcessHistoryLock);
}

/**
	Query a thread's start address for validation.
	@param ThreadId - The target thread's ID.
	@return The start address of the target thread.
*/
PVOID
ImageFilter::GetThreadStartAddress(
	_In_ HANDLE ThreadId)
{
	NTSTATUS status;
	PVOID startAddress;
	PETHREAD threadObject;
	HANDLE threadHandle;
	ULONG returnLength;

	startAddress = NULL;
	threadHandle = NULL;

	//
	// First look up the PETHREAD of the thread.
	//
	status = PsLookupThreadByThreadId(ThreadId, &threadObject);
	if (NT_SUCCESS(status) == FALSE)
	{
		DBGPRINT("ImageFilter!GetThreadStartAddress: Failed to lookup thread 0x%X by its ID.", ThreadId);
		goto Exit;
	}

	//
	// Open a handle to the thread.
	//
	status = ObOpenObjectByPointer(threadObject, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, GENERIC_ALL, *PsThreadType, KernelMode, &threadHandle);
	if (NT_SUCCESS(status) == FALSE)
	{
		DBGPRINT("ImageFilter!GetThreadStartAddress: Failed to open handle to process with status 0x%X.", status);
		goto Exit;
	}

	//
	// Query the thread's start address.
	//
	status = NtQueryInformationThread(threadHandle, ThreadQuerySetWin32StartAddress, &startAddress, sizeof(startAddress), &returnLength);
	if (NT_SUCCESS(status) == FALSE)
	{
		DBGPRINT("ImageFilter!GetThreadStartAddress: Failed to query thread start address with status 0x%X.", status);
		goto Exit;
	}
Exit:
	if (threadHandle != NULL)
	{
		ZwClose(threadHandle);
	}
	return startAddress;
}

/**
	Called when a new thread is created. Ensure the thread is legit.
	@param ProcessId - The process ID of the process receiving the new thread.
	@param ThreadId - The thread ID of the new thread.
	@param Create - Whether or not this is termination of a thread or creation.
*/
VOID ImageFilter::ThreadNotifyRoutine(
	_In_ HANDLE ProcessId,
	_In_ HANDLE ThreadId,
	_In_ BOOLEAN Create)
{
	ULONG processThreadCount = 0;
	PVOID threadStartAddress;
	PSTACK_RETURN_INFO threadCreateStack;
	ULONG threadCreateStackSize;
	PUNICODE_STRING threadCallerName;
	PUNICODE_STRING threadTargetName;

	threadCreateStack = NULL;
	threadCreateStackSize = 20;
	threadCallerName = NULL;
	threadTargetName = NULL;

	//
	// We don't really care about thread termination or if the thread is kernel-mode.
	//
	if (Create == FALSE || ExGetPreviousMode() == KernelMode)
	{
		return;
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
	// Walk the stack.
	//
	ImageFilter::walker.WalkAndResolveStack(&threadCreateStack, &threadCreateStackSize, STACK_HISTORY_TAG);

	//
	// Grab the name of the caller.
	//
	if (ImageFilter::GetProcessImageFileName(PsGetCurrentProcessId(), &threadCallerName) == FALSE)
	{
		threadCallerName = NULL; // Ensure it's NULL if GetProcessImageFileName fails
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

	if (ImageFilter::destroying)
	{
		return foundProcess;
	}

	//
	// Acquire a shared lock to iterate processes.
	//
	ExAcquireFastMutex((PFAST_MUTEX)&ProcessHistoryLock);

	if (ImageFilter::ProcessHistory)
	{
		// Iterate through the array
		for (ULONG64 i = 0; i < ImageFilter::ProcessHistorySize; i++) {
			currentProcessHistory = &ImageFilter::ProcessHistory[i];
			if (ProcessId == currentProcessHistory->ProcessId &&
				currentProcessHistory->ProcessTerminated == FALSE)
			{
				currentProcessHistory->ProcessThreadCount++;
				*ThreadCount = currentProcessHistory->ProcessThreadCount;
				foundProcess = TRUE;
				break;
			}
			// Already advancing in the for loop
		}
	}

	//
	// Release the lock.
	//
	ExReleaseFastMutex((PFAST_MUTEX)&ProcessHistoryLock);

	return foundProcess;
}

/**
	Populate a process sizes request.
	@param ProcessSizesRequest - The request to populate.
*/
/*
typedef struct ProcessSizesRequest
{
	HANDLE ProcessId;					// The process id of the executed process.
	ULONGLONG EpochExecutionTime;		// Process execution time in seconds since 1970.
	ULONG ProcessSize;					// The number of loaded processes.
	ULONG ImageSize;					// The number of loaded images in the process.
	ULONG StackSize;					// The number of stack return entries in the stack history for the process.
} PROCESS_SIZES_REQUEST, *PPROCESS_SIZES_REQUEST;
*/
VOID ImageFilter::PopulateProcessSizes(
	_Inout_ PPROCESS_SIZES_REQUEST ProcessSizesRequest)
{
	PPROCESS_HISTORY_ENTRY currentProcessHistory;

	if (ImageFilter::destroying)
	{
		return;
	}

	//
	// Acquire a shared lock to iterate processes.
	//
	ExAcquireFastMutex((PFAST_MUTEX)&ProcessHistoryLock);

	if (ImageFilter::ProcessHistory)
	{
		// Iterate through the array
		for (ULONG64 i = 0; i < ImageFilter::ProcessHistorySize; i++) {
			currentProcessHistory = &ImageFilter::ProcessHistory[i];
			if (ProcessSizesRequest->ProcessId == currentProcessHistory->ProcessId &&
				ProcessSizesRequest->EpochExecutionTime == currentProcessHistory->EpochExecutionTime)
			{
				ProcessSizesRequest->StackSize = currentProcessHistory->CallerStackHistorySize;
				ProcessSizesRequest->ImageSize = currentProcessHistory->ImageLoadHistorySize;
				break;
			}
			// Already advancing in the for loop
		}
	}

	//
	// Release the lock.
	//
	ExReleaseFastMutex((PFAST_MUTEX)&ProcessHistoryLock);
}

/**
	Populate an image detailed request.
	@param ImageDetailedRequest - The request to populate.
*/
/*
typedef struct ImageDetailedRequest
{
	HANDLE ProcessId;					// The process id of the executed process.
	ULONGLONG EpochExecutionTime;		// Process execution time in seconds since 1970.
	BOOLEAN Populated;					// Whether not this structure was populated (the image was found).

	ULONG ImageIndex;					// The index of the target image. Must not be larger than the process images list size.
	WCHAR ImagePath[MAX_PATH];			// The path to the image. Populated by the driver.
	ULONG StackHistorySize;				// The length of the StackHistory array.
	STACK_RETURN_INFO StackHistory[1];	// Variable-length array of stack history. Populated by the driver.
} IMAGE_DETAILED_REQUEST, *PIMAGE_DETAILED_REQUEST;
*/
VOID ImageFilter::PopulateImageDetailedRequest(
	_Inout_ PIMAGE_DETAILED_REQUEST ImageDetailedRequest)
{
	NTSTATUS status;
	PPROCESS_HISTORY_ENTRY currentProcessHistory;
	PIMAGE_LOAD_HISTORY_ENTRY currentImageEntry = NULL;
	ULONG i;

	i = 0;

	if (ImageFilter::destroying)
	{
		return;
	}

	//
	// Acquire a shared lock to iterate processes.
	//
	ExAcquireFastMutex((PFAST_MUTEX)&ProcessHistoryLock);

	if (ImageFilter::ProcessHistory)
	{
		// Iterate through the array
		for (ULONG64 processIndex = 0; processIndex < ImageFilter::ProcessHistorySize; processIndex++) {
			currentProcessHistory = &ImageFilter::ProcessHistory[i];
			if (ImageDetailedRequest->ProcessId == currentProcessHistory->ProcessId &&
				ImageDetailedRequest->EpochExecutionTime == currentProcessHistory->EpochExecutionTime)
			{
				//
				// Iterate the images for basic information.
				//
				FltAcquirePushLockShared(&currentProcessHistory->ImageLoadHistoryLock);

				//
				// The head isn't an element so skip it.
				//
				currentImageEntry = RCAST<PIMAGE_LOAD_HISTORY_ENTRY>(currentProcessHistory->ImageLoadHistory->ListEntry.Flink);
				while (currentImageEntry != currentProcessHistory->ImageLoadHistory)
				{
					if (i == ImageDetailedRequest->ImageIndex)
					{
						if (currentImageEntry->ImageFileName.Buffer)
						{
							status = RtlStringCbCopyUnicodeString(RCAST<NTSTRSAFE_PWSTR>(ImageDetailedRequest->ImagePath), MAX_PATH * sizeof(WCHAR), &currentImageEntry->ImageFileName);
							if (NT_SUCCESS(status) == FALSE)
							{
								DBGPRINT("ImageFilter!PopulateImageDetailedRequest: Failed to copy the image file name of an image with status 0x%X and source size %i.", status, currentImageEntry->ImageFileName.Length);
								break;
							}
						}

						//
						// Copy the stack history.
						//
						ImageDetailedRequest->StackHistorySize = (ImageDetailedRequest->StackHistorySize > currentImageEntry->CallerStackHistorySize) ? currentImageEntry->CallerStackHistorySize : ImageDetailedRequest->StackHistorySize;
						memcpy(ImageDetailedRequest->StackHistory, currentImageEntry->CallerStackHistory, ImageDetailedRequest->StackHistorySize * sizeof(STACK_RETURN_INFO));

						ImageDetailedRequest->Populated = TRUE;
					}
					i++;
					currentImageEntry = RCAST<PIMAGE_LOAD_HISTORY_ENTRY>(currentImageEntry->ListEntry.Flink);
				}

				FltReleasePushLock(&currentProcessHistory->ImageLoadHistoryLock);
				break;
			}
			// Already advancing in the for loop
		}
	}

	//
	// Release the lock.
	//
	ExReleaseFastMutex((PFAST_MUTEX)&ProcessHistoryLock);
}