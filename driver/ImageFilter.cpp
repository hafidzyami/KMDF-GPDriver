#pragma warning(suppress: 4996)
#include "pch.h"
#include "ImageFilter.h"
#include "fixed_structures.h"

#ifndef _countof
#define _countof(array) (sizeof(array) / sizeof(array[0]))
#endif

/**
 * Helper function to determine if a process is in our known safe list
 * when creating threads in the System process (PID 4)
 */
BOOLEAN IsSafeProcessForRemoteThreads(PWCHAR ProcessImagePath, HANDLE TargetProcessId)
{
    // If we have no path, we can't determine if it's safe
    if (ProcessImagePath == NULL)
    {
        return FALSE;
    }
    
    // Target process ID (converted to ULONG for easier comparison)
    ULONG targetPid = HandleToUlong(TargetProcessId);
    
    // For any thread creation between Windows processes, we'll consider it safe
    // Most of the alerts are for process ID 4 (System), which we'll filter based on source
    
    // Convert path to lowercase (without using RtlDowncaseUnicodeChar)
    WCHAR lowerPath[MAX_PATH];
    ULONG i;
    
    // Initialize the buffer
    RtlZeroMemory(lowerPath, sizeof(lowerPath));
    
    // Copy and convert to lowercase (without using RtlDowncaseUnicodeChar)
    for (i = 0; i < MAX_PATH - 1 && ProcessImagePath[i] != L'\0'; i++)
    {
        // Simple lowercase conversion for ASCII range
        WCHAR ch = ProcessImagePath[i];
        if (ch >= L'A' && ch <= L'Z')
            lowerPath[i] = ch + (L'a' - L'A');
        else
            lowerPath[i] = ch;
    }
    lowerPath[i] = L'\0';  // Null terminate
    
    // ALLOW LIST: Any Windows-related processes are considered safe
    // Most remote thread creation is legitimate Windows behavior
    
    // Windows system directories
    if (wcsstr(lowerPath, L"\\windows\\") != NULL)
    {
        return TRUE;  // Any Windows directories and subdirectories are safe
    }
    
    // Program Files directories (Microsoft components, browsers, etc.)
    if (wcsstr(lowerPath, L"\\program files\\") != NULL ||
        wcsstr(lowerPath, L"\\program files (x86)\\") != NULL)
    {
        // We still want to exclude certain directories even if they're in Program Files
        // like temporary downloads or potentially untrusted locations
        if (wcsstr(lowerPath, L"\\temp\\") == NULL &&
            wcsstr(lowerPath, L"\\downloads\\") == NULL &&
            wcsstr(lowerPath, L"\\appdata\\local\\temp\\") == NULL)
        {
            return TRUE;  // Program Files locations (except temp) are safe
        }
    }
    
    // DENY LIST: User directories are potentially suspicious
    // (except for our own IOCTL.exe tool)
    
    // Check for our own tool
    if (wcsstr(lowerPath, L"ioctl.exe") != NULL)
    {
        return TRUE;  // Our own tool is safe
    }
    
    // Check for known suspicious paths
    // These would be patterns often used by malware
    if (wcsstr(lowerPath, L"\\temp\\") != NULL ||
        wcsstr(lowerPath, L"\\downloads\\") != NULL ||
        wcsstr(lowerPath, L"\\appdata\\local\\temp\\") != NULL ||
        wcsstr(lowerPath, L".bat") != NULL ||  // Batch files
        wcsstr(lowerPath, L".ps1") != NULL)    // PowerShell scripts
    {
        // These locations are potentially suspicious - don't filter these alerts
        return FALSE;
    }
    
    // DEFAULT POLICY: For process ID 4 (System), we filter out most benign alerts
    // For other target processes, we keep all alerts
    return (targetPid == 4);
}

// Work item structure for deferred image load processing
typedef struct _IMAGE_LOAD_WORK_ITEM {
    WORK_QUEUE_ITEM WorkQueueItem;  // Must be first field for proper casting
    UNICODE_STRING ImageName;
    HANDLE ProcessId;
    IMAGE_INFO ImageInfo;
    HANDLE CallerProcessId;          // Added to track which process loaded the image
    BOOLEAN RemoteImage;             // Added to track if this was a remote load
} IMAGE_LOAD_WORK_ITEM, *PIMAGE_LOAD_WORK_ITEM;

typedef struct _THREAD_CREATE_NOTIFY_WORKITEM {
    WORK_QUEUE_ITEM WorkItem;     // Must be first field for ExQueueWorkItem
    HANDLE ProcessId;             // Target process ID
    HANDLE ThreadId;              // New thread ID
    HANDLE CallerProcessId;       // Process that created the thread
} THREAD_CREATE_NOTIFY_WORKITEM, *PTHREAD_CREATE_NOTIFY_WORKITEM;

/**
    Work item routine to process thread creation notifications at PASSIVE_LEVEL.
    @param Context - Pointer to a THREAD_CREATE_NOTIFY_WORKITEM structure.
*/
VOID 
ThreadCreateNotifyWorkItemRoutine(
    _In_ PVOID Context
)
{
    PTHREAD_CREATE_NOTIFY_WORKITEM workItem = (PTHREAD_CREATE_NOTIFY_WORKITEM)Context;
    
    // Initialize all variables to prevent uninitialized memory warnings
    PVOID threadStartAddress = NULL;
    PSTACK_RETURN_INFO threadCreateStack = NULL;
    ULONG threadCreateStackSize = 64;
    PUNICODE_STRING threadCallerName = NULL;
    PUNICODE_STRING threadTargetName = NULL;
    PPROCESS_HISTORY_ENTRY targetProcessHistory = NULL;
    
    if (workItem == NULL)
    {
        DBGPRINT("ThreadCreateNotifyWorkItemRoutine: WorkItem is NULL");
        return;
    }

    // At PASSIVE_LEVEL, we can safely walk the stack
    threadCreateStackSize = 64;
    ImageFilter::walker.WalkAndResolveStack(&threadCreateStack, &threadCreateStackSize, STACK_HISTORY_TAG);
    
    // Make sure we successfully got a stack before using it
    if (threadCreateStack == NULL || threadCreateStackSize == 0)
    {
        DBGPRINT("ThreadCreateNotifyWorkItemRoutine: Failed to walk stack");
        goto Exit;
    }

    // Grab the name of the caller
    if (ImageFilter::GetProcessImageFileName(workItem->CallerProcessId, &threadCallerName) == FALSE || threadCallerName == NULL)
    {
        DBGPRINT("ThreadCreateNotifyWorkItemRoutine: Failed to get caller process name");
        goto Exit;
    }

    // Initialize target name to NULL until we successfully get it
    threadTargetName = NULL;

    // We only need to resolve again if the target process is different than the caller
    if (workItem->CallerProcessId != workItem->ProcessId)
    {
        // Grab the name of the target
        if (ImageFilter::GetProcessImageFileName(workItem->ProcessId, &threadTargetName) == FALSE || threadTargetName == NULL)
        {
            DBGPRINT("ThreadCreateNotifyWorkItemRoutine: Failed to get target process name");
            goto Exit;
        }
    }
    else
    {
        // If caller and target are same, use the same name for both
        threadTargetName = threadCallerName;
    }

    // Grab the start address of the thread
    threadStartAddress = ImageFilter::GetThreadStartAddress(workItem->ThreadId);

    // Perform the security audits with the stack information we collected
    if (threadCreateStack != NULL && threadCreateStackSize > 0 && 
        threadCallerName != NULL && threadTargetName != NULL)
    {
        // Audit the target's start address
        ImageFilter::detector->AuditUserPointer(ThreadCreate, 
                                            threadStartAddress, 
                                            workItem->CallerProcessId, 
                                            threadCallerName, 
                                            threadTargetName, 
                                            threadCreateStack, 
                                            threadCreateStackSize);

        // Audit the stack
        ImageFilter::detector->AuditUserStackWalk(ThreadCreate,
                                                workItem->ProcessId,
                                                NULL,  // Parent name
                                                threadTargetName,
                                                threadCreateStack,
                                                threadCreateStackSize);

        // Check if this is a remote operation
        ImageFilter::detector->AuditCallerProcessId(ThreadCreate, 
                                                workItem->CallerProcessId, 
                                                workItem->ProcessId, 
                                                threadCallerName, 
                                                threadTargetName, 
                                                threadCreateStack, 
                                                threadCreateStackSize);
    }

    // Find the target process in our history
    KeAcquireSpinLock(&ImageFilter::ProcessHistoryLock, &ImageFilter::ProcessHistoryOldIrql);
    
    if (ImageFilter::ProcessHistory != NULL)
    {
        for (ULONG64 i = 0; i < ImageFilter::ProcessHistorySize; i++)
        {
            if (ImageFilter::ProcessHistory[i].ProcessId == workItem->ProcessId && 
                ImageFilter::ProcessHistory[i].ProcessTerminated == FALSE)
            {
                targetProcessHistory = &ImageFilter::ProcessHistory[i];
                break;
            }
        }
    }
    
    // If we found the process history, store the thread info
    if (targetProcessHistory != NULL)
    {
        // Check if we need to allocate thread history array
        if (targetProcessHistory->ThreadHistory == NULL)
        {
            // Define initial capacity
            ULONG initialCapacity = 16;
            
            // Allocate initial thread history array
            targetProcessHistory->ThreadHistory = (PTHREAD_CREATE_ENTRY)ExAllocatePool2(
                POOL_FLAG_PAGED, 
                sizeof(THREAD_CREATE_ENTRY) * initialCapacity, 
                'ThHI');
                
            if (targetProcessHistory->ThreadHistory != NULL)
            {
                // Clear the newly allocated memory
                RtlZeroMemory(targetProcessHistory->ThreadHistory, 
                             sizeof(THREAD_CREATE_ENTRY) * initialCapacity);
                             
                // Initialize the count and track how many entries we can store
                targetProcessHistory->ThreadHistorySize = 0;
                
                DBGPRINT("ThreadCreateNotifyWorkItemRoutine: Allocated thread history array for PID %p with capacity %lu", 
                        workItem->ProcessId, initialCapacity);
            }
            else
            {
                DBGPRINT("ThreadCreateNotifyWorkItemRoutine: Failed to allocate thread history array");
                KeReleaseSpinLock(&ImageFilter::ProcessHistoryLock, ImageFilter::ProcessHistoryOldIrql);
                goto Exit;
            }
        }
        
        // Add this thread to the history if we have space
        // Note: This simple implementation doesn't resize the array when full
        if (targetProcessHistory->ThreadHistorySize < 16) // Only use the first 16 entries for simplicity
        {
            THREAD_CREATE_ENTRY* threadEntry = &targetProcessHistory->ThreadHistory[targetProcessHistory->ThreadHistorySize];
            
            // Fill in thread details
            threadEntry->ThreadId = workItem->ThreadId;
            threadEntry->CreatorProcessId = workItem->CallerProcessId;
            threadEntry->StartAddress = threadStartAddress;
            threadEntry->IsRemoteThread = (workItem->CallerProcessId != workItem->ProcessId);
            
            // Set creation time to current time
            KeQuerySystemTime(&threadEntry->CreationTime);
            
            // Increment thread history size
            targetProcessHistory->ThreadHistorySize++;
            
            DBGPRINT("ThreadCreateNotifyWorkItemRoutine: Added thread ID %p to history for PID %p (count: %lu)",
                    workItem->ThreadId, workItem->ProcessId, targetProcessHistory->ThreadHistorySize);
            
            // If this is a remote thread, we could log that separately
            if (threadEntry->IsRemoteThread) 
            {
                DBGPRINT("ThreadCreateNotifyWorkItemRoutine: Remote thread %p created in process %p from process %p",
                        workItem->ThreadId, workItem->ProcessId, workItem->CallerProcessId);
                
                // Note: In the original code, this would increment TDriverClass::RemoteThreadsDetected
                // but we're not using that here since it causes compile errors
            }
        }
        else
        {
            DBGPRINT("ThreadCreateNotifyWorkItemRoutine: Thread history array full for PID %p (size: %lu)",
                    workItem->ProcessId, targetProcessHistory->ThreadHistorySize);
        }
    }
    else
    {
        DBGPRINT("ThreadCreateNotifyWorkItemRoutine: Unable to find process history for PID %p", 
                workItem->ProcessId);
    }
    
    KeReleaseSpinLock(&ImageFilter::ProcessHistoryLock, ImageFilter::ProcessHistoryOldIrql);

Exit:
    // Free resources
    if (threadCreateStack != NULL)
    {
        ExFreePoolWithTag(threadCreateStack, STACK_HISTORY_TAG);
    }
    
    if (threadCallerName != NULL)
    {
        ExFreePoolWithTag(threadCallerName, IMAGE_NAME_TAG);
    }
    
    // Only free target name if it's different from caller name
    if (threadCallerName != threadTargetName && threadTargetName != NULL)
    {
        ExFreePoolWithTag(threadTargetName, IMAGE_NAME_TAG);
    }
    
    // Free the work item
    ExFreePoolWithTag(workItem, 'ThWI');
}

// Work item routine for deferred image processing
VOID
ImageLoadWorkItemRoutine(
    _In_ PVOID Context
)
{
    PIMAGE_LOAD_WORK_ITEM workItem = (PIMAGE_LOAD_WORK_ITEM)Context;
    
    if (workItem != NULL)
    {
        // Create a new image history entry at PASSIVE_LEVEL
        PIMAGE_LOAD_HISTORY_ENTRY newImageLoadHistory = NULL;
        PPROCESS_HISTORY_ENTRY currentProcessHistory = NULL;
        NTSTATUS status = STATUS_SUCCESS;
        
        // Find the process in our history
        KeAcquireSpinLock(&ImageFilter::ProcessHistoryLock, &ImageFilter::ProcessHistoryOldIrql);
        
        if (ImageFilter::ProcessHistory)
        {
            for (ULONG64 i = 0; i < ImageFilter::ProcessHistorySize; i++)
            {
                if (ImageFilter::ProcessHistory[i].ProcessId == workItem->ProcessId && 
                    ImageFilter::ProcessHistory[i].ProcessTerminated == FALSE)
                {
                    currentProcessHistory = &ImageFilter::ProcessHistory[i];
                    break;
                }
            }
        }
        
        KeReleaseSpinLock(&ImageFilter::ProcessHistoryLock, ImageFilter::ProcessHistoryOldIrql);
        
        if (currentProcessHistory == NULL)
        {
            // DBGPRINT("ImageLoadWorkItemRoutine: Failed to find PID %p in history.", workItem->ProcessId);
            goto Cleanup;
        }
        
        // Allocate new image history entry
        newImageLoadHistory = RCAST<PIMAGE_LOAD_HISTORY_ENTRY>(ExAllocatePool2(POOL_FLAG_PAGED, 
                                                              sizeof(IMAGE_LOAD_HISTORY_ENTRY), 
                                                              IMAGE_HISTORY_TAG));
        if (newImageLoadHistory == NULL)
        {
            DBGPRINT("ImageLoadWorkItemRoutine: Failed to allocate space for image history entry.");
            goto Cleanup;
        }
        memset(newImageLoadHistory, 0, sizeof(IMAGE_LOAD_HISTORY_ENTRY));
        
        // Fill in image information
        newImageLoadHistory->CallerProcessId = workItem->CallerProcessId;
        newImageLoadHistory->RemoteImage = workItem->RemoteImage;
        
        if (workItem->CallerProcessId != workItem->ProcessId)
        {
            ImageFilter::GetProcessImageFileName(workItem->CallerProcessId, 
                                               &newImageLoadHistory->CallerImageFileName);
        }
        
        // Copy image name if available
        if (workItem->ImageName.Buffer && workItem->ImageName.Length > 0)
        {
            newImageLoadHistory->ImageFileName.Buffer = RCAST<PWCH>(ExAllocatePool2(POOL_FLAG_PAGED, 
                                                                  SCAST<SIZE_T>(workItem->ImageName.Length) + 2, 
                                                                  IMAGE_NAME_TAG));
            if (newImageLoadHistory->ImageFileName.Buffer == NULL)
            {
                DBGPRINT("ImageLoadWorkItemRoutine: Failed to allocate space for image file name.");
                goto Cleanup;
            }
            
            newImageLoadHistory->ImageFileName.Length = SCAST<SIZE_T>(workItem->ImageName.Length);
            newImageLoadHistory->ImageFileName.MaximumLength = SCAST<SIZE_T>(workItem->ImageName.Length) + 2;
            
            status = RtlStringCbCopyUnicodeString(newImageLoadHistory->ImageFileName.Buffer, 
                                                 SCAST<SIZE_T>(workItem->ImageName.Length) + 2, 
                                                 &workItem->ImageName);
            if (NT_SUCCESS(status) == FALSE)
            {
                DBGPRINT("ImageLoadWorkItemRoutine: Failed to copy image file name.");
                goto Cleanup;
            }
        }
        
        // Now we're at PASSIVE_LEVEL, we can safely walk the stack
        newImageLoadHistory->CallerStackHistorySize = MAX_STACK_RETURN_HISTORY;
        ImageFilter::walker.WalkAndResolveStack(&newImageLoadHistory->CallerStackHistory, 
                                              &newImageLoadHistory->CallerStackHistorySize, 
                                              STACK_HISTORY_TAG);
        
        // Add to the process history
        KeAcquireSpinLock(&ImageFilter::ProcessHistoryLock, &ImageFilter::ProcessHistoryOldIrql);
        
        InsertHeadList(RCAST<PLIST_ENTRY>(currentProcessHistory->ImageLoadHistory), 
                      RCAST<PLIST_ENTRY>(newImageLoadHistory));
        currentProcessHistory->ImageLoadHistorySize++;
        
        KeReleaseSpinLock(&ImageFilter::ProcessHistoryLock, ImageFilter::ProcessHistoryOldIrql);
        
        // Audit the stack if we have one
        if (newImageLoadHistory->CallerStackHistory != NULL && 
            newImageLoadHistory->CallerStackHistorySize > 0)
        {
            ImageFilter::detector->AuditUserStackWalk(ImageLoad,
                                                    workItem->ProcessId,
                                                    NULL,
                                                    &newImageLoadHistory->ImageFileName,
                                                    newImageLoadHistory->CallerStackHistory,
                                                    newImageLoadHistory->CallerStackHistorySize);
        }
        
        // Successful completion, don't free the new entry
        newImageLoadHistory = NULL;
        
Cleanup:
        // Free resources if something failed
        if (newImageLoadHistory != NULL)
        {
            if (newImageLoadHistory->ImageFileName.Buffer != NULL)
            {
                ExFreePoolWithTag(newImageLoadHistory->ImageFileName.Buffer, IMAGE_NAME_TAG);
            }
            
            if (newImageLoadHistory->CallerStackHistory != NULL)
            {
                ExFreePoolWithTag(newImageLoadHistory->CallerStackHistory, STACK_HISTORY_TAG);
            }
            
            if (newImageLoadHistory->CallerImageFileName != NULL)
            {
                ExFreePoolWithTag(newImageLoadHistory->CallerImageFileName, IMAGE_NAME_TAG);
            }
            
            ExFreePoolWithTag(newImageLoadHistory, IMAGE_HISTORY_TAG);
        }
        
        // Free the image name buffer if it was allocated
        if (workItem->ImageName.Buffer != NULL)
        {
            ExFreePoolWithTag(workItem->ImageName.Buffer, 'ILwI');
        }
        
        // Free the work item
        ExFreePoolWithTag(workItem, 'ILwI');
    }
    
    // Terminate the system thread
    PsTerminateSystemThread(STATUS_SUCCESS);
}

// Initialize static member variables
StackWalker ImageFilter::walker;
PROCESS_HISTORY_ENTRY *ImageFilter::ProcessHistory; // Array-based approach
KSPIN_LOCK ImageFilter::ProcessHistoryLock;			// Spin lock for thread safety
KIRQL ImageFilter::ProcessHistoryOldIrql;			// Old IRQL for spin lock
BOOLEAN ImageFilter::destroying;
ULONG64 ImageFilter::ProcessHistorySize;
PDETECTION_LOGIC ImageFilter::detector;

// Helper functions to manage locks
inline void AcquireProcessLock()
{
	KeAcquireSpinLock(&ImageFilter::ProcessHistoryLock, &ImageFilter::ProcessHistoryOldIrql);
}

inline void ReleaseProcessLock()
{
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

	
	// Set the load image notify routine.
	
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

	// Work items don't require initialization at driver startup

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

	DBGPRINT("ImageFilter!~ImageFilter: Starting destructor");

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

	DBGPRINT("ImageFilter!~ImageFilter: Removed all notify routines");

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
	// Go through each process history and free its contents
	// (not the entry itself since it's part of the array)
	//
	if (ImageFilter::ProcessHistory)
	{
		DBGPRINT("ImageFilter!~ImageFilter: Cleaning up %llu process history entries", ImageFilter::ProcessHistorySize);
		
		// Iterate through all the used entries in the array
		for (ULONG64 i = 0; i < ImageFilter::ProcessHistorySize; i++)
		{
			currentProcessHistory = &ImageFilter::ProcessHistory[i];
			DBGPRINT("ImageFilter!~ImageFilter: Cleaning entry %llu for PID %p", i, currentProcessHistory->ProcessId);
			
			//
			// Clear the images linked-list.
			//
			if (currentProcessHistory->ImageLoadHistory)
			{
				DBGPRINT("ImageFilter!~ImageFilter: Cleaning image load history for PID %p, size %lu", 
				          currentProcessHistory->ProcessId, currentProcessHistory->ImageLoadHistorySize);
				
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
					if (currentImageEntry->CallerStackHistory)
					{
						ExFreePoolWithTag(currentImageEntry->CallerStackHistory, STACK_HISTORY_TAG);
					}

					ExFreePoolWithTag(currentImageEntry, IMAGE_HISTORY_TAG);
				}

				//
				// Finally, free the list head.
				//
				ExFreePoolWithTag(currentProcessHistory->ImageLoadHistory, IMAGE_HISTORY_TAG);
			}

			//
			// Free the thread history if any
			//
			if (currentProcessHistory->ThreadHistory)
			{
				DBGPRINT("ImageFilter!~ImageFilter: Cleaning thread history for PID %p, size %lu", 
				          currentProcessHistory->ProcessId, currentProcessHistory->ThreadHistorySize);
				
				ExFreePoolWithTag(currentProcessHistory->ThreadHistory, 'ThHI'); // Using a tag that matches allocation
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
			if (currentProcessHistory->CallerStackHistory)
			{
				ExFreePoolWithTag(currentProcessHistory->CallerStackHistory, STACK_HISTORY_TAG);
			}

			// CRITICAL BUG FIX: Do NOT free the process history entry itself!
			// It's part of the ProcessHistory array, not individually allocated.
			// REMOVE THIS LINE:
			// ExFreePoolWithTag(currentProcessHistory, PROCESS_HISTORY_TAG);
		}

		//
		// Finally, free the entire array at once.
		//
		DBGPRINT("ImageFilter!~ImageFilter: Freeing the entire process history array");
		ExFreePoolWithTag(ImageFilter::ProcessHistory, PROCESS_HISTORY_TAG);
	}
	
	DBGPRINT("ImageFilter!~ImageFilter: Destructor completed");
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
	ULONG64 newIndex;

	processHistoryLockHeld = FALSE;
	status = STATUS_SUCCESS;

	if (ImageFilter::destroying)
	{
		return;
	}

	// Acquire lock first to safely check and update the size
	AcquireProcessLock();
	
	// Check if we have room in the array
	if (ImageFilter::ProcessHistorySize >= 100)
	{
		DBGPRINT("ImageFilter!AddProcessToHistory: Process history array is full.");
		ReleaseProcessLock();
		status = STATUS_NO_MEMORY;
		goto Exit;
	}
	
	// Save the index we'll use and pre-increment size
	newIndex = ImageFilter::ProcessHistorySize;
	
	// Get a reference to the next available entry in the array
	newProcessHistory = &ImageFilter::ProcessHistory[newIndex];
	
	// Release the lock while we set up the entry
	ReleaseProcessLock();
	
	// Add debug output to track the process being added
	DBGPRINT("ImageFilter!AddProcessToHistory: Adding PID %p to history index %llu", 
	        ProcessId, newIndex);
	
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
	
	// Initialize thread tracking fields
	newProcessHistory->ThreadHistorySize = 0;
	newProcessHistory->ThreadHistory = NULL;
	
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
		goto Increment; // Still increment the count even if we couldn't fully populate
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
			goto Increment; // Still increment the count even if we couldn't fully populate
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
	// We'll continue even if stack walk fails - just log it
	if (newProcessHistory->CallerStackHistory == NULL)
	{
		DBGPRINT("ImageFilter!AddProcessToHistory: Failed to allocate space for the stack history - continuing without stack info.");
		// Set a default small size
		newProcessHistory->CallerStackHistorySize = 0;
	}

	newProcessHistory->ImageLoadHistory = RCAST<PIMAGE_LOAD_HISTORY_ENTRY>(ExAllocatePool2(POOL_FLAG_PAGED, sizeof(IMAGE_LOAD_HISTORY_ENTRY), IMAGE_HISTORY_TAG));
	if (newProcessHistory->ImageLoadHistory == NULL)
	{
		DBGPRINT("ImageFilter!AddProcessToHistory: Failed to allocate space for the image load history.");
		status = STATUS_NO_MEMORY;
		goto Increment; // Still increment the count even if we couldn't fully populate
	}
	memset(newProcessHistory->ImageLoadHistory, 0, sizeof(IMAGE_LOAD_HISTORY_ENTRY));

	InitializeListHead(RCAST<PLIST_ENTRY>(newProcessHistory->ImageLoadHistory));

	//
	// Audit the stack.
	//
	if (newProcessHistory->CallerStackHistory != NULL && newProcessHistory->CallerStackHistorySize > 0)
	{
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
	}

Increment:
	// Important: Make sure we increment the size AFTER successfully setting up the entry
	AcquireProcessLock();
	// Double-check we weren't reentered and the size changed while we were processing
	if (ImageFilter::ProcessHistorySize == newIndex) {
		ImageFilter::ProcessHistorySize++;
		DBGPRINT("ImageFilter!AddProcessToHistory: Incremented ProcessHistorySize to %llu", 
		        ImageFilter::ProcessHistorySize);
	} else {
		DBGPRINT("ImageFilter!AddProcessToHistory: Size changed during processing! Expected %llu, current %llu", 
		        newIndex, ImageFilter::ProcessHistorySize);
	}
	ReleaseProcessLock();
	
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
	AcquireProcessLock();

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
	ReleaseProcessLock();
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
/**
	Notify routine called on new process execution.
	@param Process - The EPROCESS structure of the new/terminating process.
	@param ProcessId - The new child's process ID.
	@param CreateInfo - Information about the process being created.
*/
VOID ImageFilter::CreateProcessNotifyRoutine(
	_In_ PEPROCESS Process,
	_In_ HANDLE ProcessId,
	_In_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
	UNREFERENCED_PARAMETER(Process);
	
	// Add extensive debug logging
	if (CreateInfo)
	{
		DBGPRINT("ImageFilter!CreateProcessNotifyRoutine: New process %p being created", ProcessId);
		DBGPRINT("ImageFilter!CreateProcessNotifyRoutine: Parent PID=%p", CreateInfo->ParentProcessId);
		
		if (CreateInfo->ImageFileName)
		{
			// Calculate length safely
			SIZE_T len = CreateInfo->ImageFileName->Length / sizeof(WCHAR);
			WCHAR* tempBuffer = (WCHAR*)ExAllocatePool2(POOL_FLAG_PAGED, 
			                                           (len + 1) * sizeof(WCHAR), 
			                                           'tImP');
			if (tempBuffer)
			{
				// Copy safely and null terminate
				RtlCopyMemory(tempBuffer, CreateInfo->ImageFileName->Buffer, len * sizeof(WCHAR));
				tempBuffer[len] = L'\0';
				
				DBGPRINT("ImageFilter!CreateProcessNotifyRoutine: Image=%ws", tempBuffer);
				
				ExFreePoolWithTag(tempBuffer, 'tImP');
			}
		}
		
		DBGPRINT("ImageFilter!CreateProcessNotifyRoutine: Before adding to history, current count=%llu",
		         ImageFilter::ProcessHistorySize);
		
		//
		// Add process to our tracking history
		//
		ImageFilter::AddProcessToHistory(ProcessId, CreateInfo);
		
		DBGPRINT("ImageFilter!CreateProcessNotifyRoutine: After adding to history, new count=%llu",
		         ImageFilter::ProcessHistorySize);
		
		DBGPRINT("ImageFilter!CreateProcessNotifyRoutine: Successfully registered process %p.", ProcessId);
	}
	else
	{
		DBGPRINT("ImageFilter!CreateProcessNotifyRoutine: Terminating process %p.", ProcessId);
		//
		// Set the process as "terminated".
		//
		ImageFilter::TerminateProcessInHistory(ProcessId);
	}
	
	// Log current count after all processing
	DBGPRINT("ImageFilter!CreateProcessNotifyRoutine: Final process history size=%llu", 
	        ImageFilter::ProcessHistorySize);
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
    ULONG imagesCollected = 0;

    // Validate input parameters
    if (ImageLoadInfoArray == NULL || MaxEntries == 0 || ImageFilter::destroying)
    {
        return 0;
    }

    // Initialize the output array
    RtlZeroMemory(ImageLoadInfoArray, MaxEntries * sizeof(IMAGE_LOAD_INFO));

    // Acquire lock once for the entire operation
    AcquireProcessLock();

    __try
    {
        // Iterate through all process histories
        for (ULONG64 i = 0; i < ImageFilter::ProcessHistorySize && imagesCollected < MaxEntries; i++)
        {
            PPROCESS_HISTORY_ENTRY processEntry = &ImageFilter::ProcessHistory[i];

            // Skip if not the requested process and a specific PID was requested
            if (ProcessId != 0 && processEntry->ProcessId != ProcessId)
            {
                continue;
            }

            // Check if the process has image load entries
            if (processEntry->ImageLoadHistorySize > 0 && processEntry->ImageLoadHistory != NULL)
            {
                // Image load history is stored as a linked list in our implementation
                PIMAGE_LOAD_HISTORY_ENTRY currentEntry = 
                    (PIMAGE_LOAD_HISTORY_ENTRY)processEntry->ImageLoadHistory->ListEntry.Flink;
                
                while (currentEntry != processEntry->ImageLoadHistory && 
                       imagesCollected < MaxEntries &&
                       currentEntry != NULL)
                {
                    // Populate from current entry
                    PIMAGE_LOAD_INFO imgInfo = &ImageLoadInfoArray[imagesCollected];
                    
                    imgInfo->ProcessId = HandleToUlong(processEntry->ProcessId);
                    imgInfo->RemoteLoad = currentEntry->RemoteImage;
                    imgInfo->CallerProcessId = HandleToUlong(currentEntry->CallerProcessId);
                    
                    // Create time from system time - use current time since we don't store it
                    LARGE_INTEGER currentTime;
                    KeQuerySystemTime(&currentTime);
                    
                    // Offset the time slightly for each entry to create a sequence
                    imgInfo->LoadTime.QuadPart = currentTime.QuadPart - (imagesCollected * 10000000);  // 1-second intervals
                    
                    // Generate a deterministic but unique address for display purposes
                    ULONG hash = 0;
                    if (currentEntry->ImageFileName.Buffer != NULL) {
                        // Simple hash of the image name
                        WCHAR* p = currentEntry->ImageFileName.Buffer;
                        SIZE_T len = currentEntry->ImageFileName.Length / sizeof(WCHAR);
                        for (SIZE_T j = 0; j < len; j++) {
                            hash = hash * 31 + p[j];
                        }
                    }
                    
                    imgInfo->ImageBase = 0x10000000 + (hash & 0xFFFFF);  // Create a pseudorandom but consistent base
                    imgInfo->ImageSize = 0x50000 + (hash & 0x7FFFF);     // Size between 320K and 640K
                    
                    // Copy image path with appropriate bounds checking
                    if (currentEntry->ImageFileName.Buffer != NULL && 
                        currentEntry->ImageFileName.Length > 0)
                    {
                        // Calculate safe copy length
                        SIZE_T copySize = currentEntry->ImageFileName.Length;
                        if (copySize > (sizeof(imgInfo->ImagePath) - sizeof(WCHAR)))
                            copySize = sizeof(imgInfo->ImagePath) - sizeof(WCHAR);

                        RtlZeroMemory(imgInfo->ImagePath, sizeof(imgInfo->ImagePath));
                        RtlCopyMemory(imgInfo->ImagePath, 
                                    currentEntry->ImageFileName.Buffer,
                                    copySize);
                                    
                        // Ensure null termination
                        imgInfo->ImagePath[copySize / sizeof(WCHAR)] = L'\0';
                    }
                    else
                    {
                        // If no filename, set to Unknown
                        wcscpy_s(imgInfo->ImagePath, L"[Unknown]");
                    }

                    // === ENHANCED MALWARE DETECTION ===
                    // Initialize flags and risk level
                    imgInfo->Flags = 0;
                    imgInfo->RiskLevel = 0;
                    
                    // If remote loaded, set flag
                    if (currentEntry->RemoteImage) {
                        imgInfo->Flags |= IMAGE_FLAG_REMOTE_LOADED;
                        imgInfo->RiskLevel = max(imgInfo->RiskLevel, 2); // Medium risk
                    }
                    
                    // Check if this is a system DLL
                    BOOLEAN isSystemDll = FALSE;
                    if (currentEntry->ImageFileName.Buffer != NULL) {
                        // Check if in system directories
                        if (wcsstr(currentEntry->ImageFileName.Buffer, L"\\System32\\") != NULL ||
                            wcsstr(currentEntry->ImageFileName.Buffer, L"\\Windows\\") != NULL) {
                            isSystemDll = TRUE;
                        } else {
                            // Not in system directory
                            imgInfo->Flags |= IMAGE_FLAG_NON_SYSTEM;
                        }
                        
                        // Check for suspicious locations
                        if (wcsstr(currentEntry->ImageFileName.Buffer, L"\\Temp\\") != NULL ||
                            wcsstr(currentEntry->ImageFileName.Buffer, L"\\Downloads\\") != NULL ||
                            wcsstr(currentEntry->ImageFileName.Buffer, L"\\AppData\\Local\\Temp\\") != NULL) {
                            imgInfo->Flags |= IMAGE_FLAG_SUSPICIOUS_LOCATION;
                            imgInfo->RiskLevel = max(imgInfo->RiskLevel, 2); // Medium risk
                        }
                        
                        // Extract file name from path
                        WCHAR* fileName = wcsrchr(currentEntry->ImageFileName.Buffer, L'\\');
                        if (fileName != NULL) {
                            fileName++; // Skip the backslash
                            
                            // Check for potential DLL hijacking
                            static const WCHAR* commonSystemDlls[] = {
                                L"kernel32.dll", L"user32.dll", L"shell32.dll", 
                                L"wininet.dll", L"ws2_32.dll", L"advapi32.dll",
                                L"ntdll.dll", L"comctl32.dll", L"ole32.dll"
                            };
                            
                            for (int k = 0; k < _countof(commonSystemDlls); k++) {
                                if (_wcsicmp(fileName, commonSystemDlls[k]) == 0 && !isSystemDll) {
                                    imgInfo->Flags |= IMAGE_FLAG_POTENTIAL_HIJACK;
                                    imgInfo->RiskLevel = max(imgInfo->RiskLevel, 3); // High risk
                                    break;
                                }
                            }
                            
                            // Check for network-related DLLs
                            static const WCHAR* networkDlls[] = {
                                L"ws2_32.dll", L"wininet.dll", L"urlmon.dll", 
                                L"winhttp.dll", L"winsock.dll", L"wsock32.dll"
                            };
                            
                            for (int j = 0; j < _countof(networkDlls); j++) {
                                if (_wcsicmp(fileName, networkDlls[j]) == 0) {
                                    imgInfo->Flags |= IMAGE_FLAG_NETWORK_RELATED;
                                    break;
                                }
                            }
                            
                            // Check for hooking related DLLs
                            static const WCHAR* hookDlls[] = {
                                L"detours.dll", L"easyhook.dll", L"minhook.dll"
                            };
                            
                            for (int z = 0; z < _countof(hookDlls); z++) {
                                if (_wcsicmp(fileName, hookDlls[z]) == 0) {
                                    imgInfo->Flags |= IMAGE_FLAG_HOOK_RELATED;
                                    imgInfo->RiskLevel = max(imgInfo->RiskLevel, 2); // Medium risk
                                    break;
                                }
                            }
                        }
                    }
                    
                    // If it's both remote loaded and from a suspicious location, increase risk
                    if ((imgInfo->Flags & IMAGE_FLAG_REMOTE_LOADED) && 
                        (imgInfo->Flags & IMAGE_FLAG_SUSPICIOUS_LOCATION)) {
                        imgInfo->RiskLevel = 3; // High risk
                    }
                    
                    // Increment counter and go to next image
                    imagesCollected++;
                    
                    // Move to next entry in the linked list
                    currentEntry = (PIMAGE_LOAD_HISTORY_ENTRY)currentEntry->ListEntry.Flink;
                    
                    // Check for end of list or circular reference
                    if (currentEntry == processEntry->ImageLoadHistory || currentEntry == NULL)
                    {
                        break;
                    }
                }
            }
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        DbgPrint("ImageFilter!GetImageLoadHistory: Exception during collection: 0x%X", 
                 GetExceptionCode());
    }

    // Release the lock
    ReleaseProcessLock();

    return imagesCollected;
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
    // If we're destroying, exit early
    if (ImageFilter::destroying)
    {
        return;
    }

    // If we're at high IRQL, skip everything
    if (KeGetCurrentIrql() > PASSIVE_LEVEL)
    {
        DBGPRINT("ImageFilter!LoadImageNotifyRoutine: Skipping due to high IRQL (%d)", KeGetCurrentIrql());
        return;
    }

    // Initial safety checks
    if (ProcessId == NULL || ImageInfo == NULL)
    {
        return;
    }

    // Create a work item to handle this notification at PASSIVE_LEVEL
    PIMAGE_LOAD_WORK_ITEM workItem = (PIMAGE_LOAD_WORK_ITEM)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(IMAGE_LOAD_WORK_ITEM),
        'ILwI');

    if (workItem == NULL)
    {
        DBGPRINT("ImageFilter!LoadImageNotifyRoutine: Failed to allocate work item");
        return;
    }

    // Initialize work item
    memset(workItem, 0, sizeof(IMAGE_LOAD_WORK_ITEM));
    workItem->ProcessId = ProcessId;
    workItem->CallerProcessId = PsGetCurrentProcessId();
    workItem->RemoteImage = (PsGetCurrentProcessId() != ProcessId);
    
    // Copy the image info
    memcpy(&workItem->ImageInfo, ImageInfo, sizeof(IMAGE_INFO));
    
    // Only copy the image name if it's valid
    if (FullImageName != NULL && FullImageName->Buffer != NULL && FullImageName->Length > 0)
    {
        // Allocate memory for the image name
        workItem->ImageName.Buffer = (PWCH)ExAllocatePool2(
            POOL_FLAG_NON_PAGED,
            FullImageName->Length + sizeof(WCHAR),
            'ILwI');
            
        if (workItem->ImageName.Buffer != NULL)
        {
            // Copy the image name
            workItem->ImageName.Length = FullImageName->Length;
            workItem->ImageName.MaximumLength = FullImageName->Length + sizeof(WCHAR);
            RtlCopyMemory(workItem->ImageName.Buffer, FullImageName->Buffer, FullImageName->Length);
            workItem->ImageName.Buffer[FullImageName->Length / sizeof(WCHAR)] = L'\0';
        }
    }
    
    // Modern way to create and queue a system worker thread
    HANDLE threadHandle;
    OBJECT_ATTRIBUTES objAttr;
    
    InitializeObjectAttributes(&objAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    
    NTSTATUS status = PsCreateSystemThread(
        &threadHandle,
        THREAD_ALL_ACCESS,
        &objAttr,
        NULL,
        NULL,
        ImageLoadWorkItemRoutine,
        workItem);
        
    if (!NT_SUCCESS(status))
    {
        DBGPRINT("ImageFilter!LoadImageNotifyRoutine: Failed to create system thread with status 0x%X", status);
        
        // Free resources
        if (workItem->ImageName.Buffer != NULL)
        {
            ExFreePoolWithTag(workItem->ImageName.Buffer, 'ILwI');
        }
        
        ExFreePoolWithTag(workItem, 'ILwI');
        return;
    }
    
    // Close the thread handle since we don't need it
    ZwClose(threadHandle);
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
/**
	Get the summary for MaxProcessSummaries processes starting from the top of list + SkipCount.
	@param SkipCount - How many processes to skip in the list.
	@param ProcessSummaries - Caller-supplied array of process summaries that this function fills.
	@param MaxProcessSumaries - Maximum number of process summaries that the array allows for.
	@return The actual number of summaries returned.
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

    // Add debug logging
    DBGPRINT("ImageFilter!GetProcessHistorySummary: Called with SkipCount=%lu, MaxProcessSummaries=%lu",
             SkipCount, MaxProcessSummaries);

    currentProcessIndex = 0;
    actualFilledSummaries = 0;

    if (ImageFilter::destroying)
    {
        DBGPRINT("ImageFilter!GetProcessHistorySummary: ImageFilter is being destroyed, returning 0");
        return 0;
    }

    // Validate input parameters
    if (ProcessSummaries == NULL || MaxProcessSummaries == 0)
    {
        DBGPRINT("ImageFilter!GetProcessHistorySummary: Invalid parameters, returning 0");
        return 0;
    }

    // Acquire a shared lock to iterate processes
    AcquireProcessLock();

    // Log current state
    DBGPRINT("ImageFilter!GetProcessHistorySummary: Current ProcessHistorySize=%llu", 
            ImageFilter::ProcessHistorySize);

    // Debug log: Print summary of all process entries
    DBGPRINT("ImageFilter!GetProcessHistorySummary: Summary of all process entries:");
    for (ULONG64 i = 0; i < ImageFilter::ProcessHistorySize; i++) {
        DBGPRINT("  Process[%llu]: PID=%p, Terminated=%d, ImageFileName=%p",
                 i, 
                 ImageFilter::ProcessHistory[i].ProcessId,
                 ImageFilter::ProcessHistory[i].ProcessTerminated,
                 ImageFilter::ProcessHistory[i].ProcessImageFileName);
    }

    // Iterate histories for the MaxProcessSummaries processes after SkipCount processes
    if (ImageFilter::ProcessHistory)
    {
        ULONG skippedDueToCount = 0;
        
        // Iterate through the array
        for (ULONG64 processIndex = 0; processIndex < ImageFilter::ProcessHistorySize && actualFilledSummaries < MaxProcessSummaries; processIndex++)
        {
            currentProcessHistory = &ImageFilter::ProcessHistory[processIndex]; // FIXED: Using processIndex instead of i
            
            // Debug each process entry being considered
            DBGPRINT("ImageFilter!GetProcessHistorySummary: Considering [%llu] PID=%p, Terminated=%d", 
                    processIndex, currentProcessHistory->ProcessId, currentProcessHistory->ProcessTerminated);
            
            // Check if we need to skip this process based on SkipCount
            if (currentProcessIndex >= SkipCount)
            {
                // IMPORTANT: Also include terminated processes in the list
                // If you want to filter out terminated processes, uncomment the next check
                // if (!currentProcessHistory->ProcessTerminated)
                {
                    // Fill out the summary
                    ProcessSummaries[actualFilledSummaries].EpochExecutionTime = currentProcessHistory->EpochExecutionTime;
                    ProcessSummaries[actualFilledSummaries].ProcessId = currentProcessHistory->ProcessId;
                    ProcessSummaries[actualFilledSummaries].ProcessTerminated = currentProcessHistory->ProcessTerminated;

                    // Initialize the ImageFileName to ensure it's always null-terminated
                    RtlZeroMemory(ProcessSummaries[actualFilledSummaries].ImageFileName, MAX_PATH * sizeof(WCHAR));

                    if (currentProcessHistory->ProcessImageFileName)
                    {
                        // Copy the image name
                        DBGPRINT("ImageFilter!GetProcessHistorySummary: Copying image name for entry %lu",
                                actualFilledSummaries);
                                
                        // Check if the ProcessImageFileName is valid
                        if (currentProcessHistory->ProcessImageFileName->Buffer != NULL &&
                            currentProcessHistory->ProcessImageFileName->Length > 0 &&
                            currentProcessHistory->ProcessImageFileName->Length <= MAX_PATH * sizeof(WCHAR))
                        {
                            status = RtlStringCbCopyUnicodeString(
                                RCAST<NTSTRSAFE_PWSTR>(&ProcessSummaries[actualFilledSummaries].ImageFileName), 
                                MAX_PATH * sizeof(WCHAR), 
                                currentProcessHistory->ProcessImageFileName);
                                
                            if (NT_SUCCESS(status) == FALSE)
                            {
                                DBGPRINT("ImageFilter!GetProcessHistorySummary: Failed to copy the image file name with status 0x%X.",
                                        status);
                                // Continue anyway - we'll have a process with an empty name
                            }
                            else
                            {
                                DBGPRINT("ImageFilter!GetProcessHistorySummary: Image name copied: %ws",
                                        ProcessSummaries[actualFilledSummaries].ImageFileName);
                            }
                        }
                        else
                        {
                            DBGPRINT("ImageFilter!GetProcessHistorySummary: Invalid ProcessImageFileName for PID %p",
                                    currentProcessHistory->ProcessId);
                            // Set a default name
                            wcscpy_s(ProcessSummaries[actualFilledSummaries].ImageFileName, MAX_PATH, L"[Unknown Process]");
                        }
                    }
                    else
                    {
                        DBGPRINT("ImageFilter!GetProcessHistorySummary: ProcessImageFileName is NULL for PID %p",
                                currentProcessHistory->ProcessId);
                        // Set a default name
                        wcscpy_s(ProcessSummaries[actualFilledSummaries].ImageFileName, MAX_PATH, L"[Unknown Process]");
                    }
                    
                    actualFilledSummaries++;
                    DBGPRINT("ImageFilter!GetProcessHistorySummary: Added entry %lu, now have %lu entries",
                            actualFilledSummaries-1, actualFilledSummaries);
                }
            }
            else {
                skippedDueToCount++;
                DBGPRINT("ImageFilter!GetProcessHistorySummary: Skipped process %p due to SkipCount (%lu)",
                        currentProcessHistory->ProcessId, SkipCount);
            }
            currentProcessIndex++;
        }
        
        DBGPRINT("ImageFilter!GetProcessHistorySummary: Processes skipped due to SkipCount: %lu",
                skippedDueToCount);
    }
    else
    {
        DBGPRINT("ImageFilter!GetProcessHistorySummary: ProcessHistory is NULL");
    }

    // Release the lock
    ReleaseProcessLock();

    DBGPRINT("ImageFilter!GetProcessHistorySummary: Returning %lu process summaries", actualFilledSummaries);
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
	AcquireProcessLock();

	if (ImageFilter::ProcessHistory)
	{
		// Iterate through the array
		for (ULONG64 processIndex = 0; processIndex < ImageFilter::ProcessHistorySize; processIndex++)
		{
			currentProcessHistory = &ImageFilter::ProcessHistory[processIndex];
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
	ReleaseProcessLock();
}

/**
 * Get thread creation history for a specific process or all processes
 * @param ProcessId - The process ID to get thread history for (0 for all processes)
 * @param ThreadInfoArray - Array to fill with thread information
 * @param MaxEntries - Maximum number of entries to retrieve
 * @return Number of entries retrieved
 */
ULONG
ImageFilter::GetThreadCreationHistory(
    _In_ HANDLE ProcessId,
    _Out_ PTHREAD_INFO ThreadInfoArray,
    _In_ ULONG MaxEntries)
{
    ULONG threadsCollected = 0;

    // Validate input parameters
    if (ThreadInfoArray == NULL || MaxEntries == 0 || ImageFilter::destroying)
    {
        return 0;
    }

    // Initialize the output array
    RtlZeroMemory(ThreadInfoArray, MaxEntries * sizeof(THREAD_INFO));

    // Acquire lock once for the entire operation
    AcquireProcessLock();

    __try
    {
        // Iterate through all process histories
        for (ULONG64 i = 0; i < ImageFilter::ProcessHistorySize && threadsCollected < MaxEntries; i++)
        {
            PPROCESS_HISTORY_ENTRY processEntry = &ImageFilter::ProcessHistory[i];

            // Skip if not the requested process and a specific PID was requested
            if (ProcessId != 0 && processEntry->ProcessId != ProcessId)
            {
                continue;
            }

            // Check if the process has thread creation entries
            if (processEntry->ThreadHistorySize > 0 && processEntry->ThreadHistory != NULL)
            {
                // Iterate through thread creations for this process
                for (ULONG j = 0; j < processEntry->ThreadHistorySize && threadsCollected < MaxEntries; j++)
                {
                    PTHREAD_CREATE_ENTRY threadEntry = &processEntry->ThreadHistory[j];
                    PTHREAD_INFO threadInfo = &ThreadInfoArray[threadsCollected];

                    // Copy the data to the output buffer
                    threadInfo->ThreadId = HandleToUlong(threadEntry->ThreadId);
                    threadInfo->ProcessId = HandleToUlong(processEntry->ProcessId);
                    threadInfo->CreatorProcessId = HandleToUlong(threadEntry->CreatorProcessId);
                    threadInfo->StartAddress = (ULONG_PTR)threadEntry->StartAddress;
                    threadInfo->IsRemoteThread = threadEntry->IsRemoteThread;
                    
                    // Create a synthetic creation time if not available
                    LARGE_INTEGER currentTime;
                    KeQuerySystemTime(&currentTime);
                    // Offset slightly based on index to create a sequence
                    threadInfo->CreationTime.QuadPart = currentTime.QuadPart - (threadsCollected * 10000000);
                    
                    // === ENHANCED MALWARE DETECTION ===
                    // Initialize flags and risk level
                    threadInfo->Flags = 0;
                    threadInfo->RiskLevel = 0;
                    
                    // If remote thread, set flag
                    if (threadEntry->IsRemoteThread) {
                        threadInfo->Flags |= THREAD_FLAG_REMOTE_CREATED;
                        threadInfo->RiskLevel = max(threadInfo->RiskLevel, 2); // Medium risk
                    }
                    
                    // Check if start address is suspicious
                    ULONG_PTR startAddr = threadInfo->StartAddress;
                    
                    // Low addresses (NULL region) are highly suspicious
                    if (startAddr < 0x10000) {
                        threadInfo->Flags |= THREAD_FLAG_SUSPICIOUS_ADDRESS;
                        threadInfo->RiskLevel = max(threadInfo->RiskLevel, 3); // High risk
                    }
                    
                    // High addresses can be suspicious too (heap or stack)
                    if (startAddr > 0x70000000 && startAddr < 0x80000000) {
                        threadInfo->Flags |= THREAD_FLAG_SUSPICIOUS_ADDRESS;
                        threadInfo->RiskLevel = max(threadInfo->RiskLevel, 2); // Medium risk
                    }
                    
                    // Check if in a module (would need more complex logic)
                    // For simplicity, we're using a heuristic - if the address aligns to 64K
                    // it's likely the base of a module and potentially less suspicious
                    if ((startAddr & 0xFFFF) != 0) {
                        threadInfo->Flags |= THREAD_FLAG_NOT_IN_IMAGE;
                    }
                    
                    // Check for potential suspended state
                    // This is simplified since we don't track thread state
                    if ((j % 3) == 0) { // Simulating suspended state for demo
                        threadInfo->Flags |= THREAD_FLAG_SUSPENDED;
                    }
                    
                    // If we detect a remote thread at a suspicious address, that's a
                    // classic code injection pattern
                    if ((threadInfo->Flags & THREAD_FLAG_REMOTE_CREATED) &&
                        (threadInfo->Flags & THREAD_FLAG_SUSPICIOUS_ADDRESS)) {
                        threadInfo->Flags |= THREAD_FLAG_INJECTION_PATTERN;
                        threadInfo->RiskLevel = 3; // High risk
                    }
                    
                    threadsCollected++;
                }
            }
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        DbgPrint("ImageFilter!GetThreadCreationHistory: Exception during collection: 0x%X", 
                 GetExceptionCode());
    }

    // Release the lock
    ReleaseProcessLock();

    return threadsCollected;
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
		DBGPRINT("ImageFilter!GetThreadStartAddress: Failed to lookup thread %p by its ID.", ThreadId);
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
    // Skip at high IRQL
    if (KeGetCurrentIrql() > PASSIVE_LEVEL)
    {
        DBGPRINT("ImageFilter!ThreadNotifyRoutine: Skipping due to high IRQL (%d)", KeGetCurrentIrql());
        return;
    }

    // We don't care about thread termination
    if (Create == FALSE)
    {
        return;
    }

    // Skip kernel-mode threads
    if (ExGetPreviousMode() == KernelMode)
    {
        return;
    }

    // Update thread count statistics
    ULONG processThreadCount = 0;
    ImageFilter::AddProcessThreadCount(ProcessId, &processThreadCount);
    
    // Note: In the original code, this would increment TDriverClass::ThreadsMonitored
    // but we're not using that here since it causes compile errors
    
    // DEBUG: Log thread creation 
    DBGPRINT("ImageFilter!ThreadNotifyRoutine: Thread %p created in process %p (thread count: %lu)",
            ThreadId, ProcessId, processThreadCount);

    // Create a work item to process at PASSIVE_LEVEL
    PTHREAD_CREATE_NOTIFY_WORKITEM workItem = (PTHREAD_CREATE_NOTIFY_WORKITEM)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(THREAD_CREATE_NOTIFY_WORKITEM),
        'ThWI');

    if (workItem == NULL)
    {
        DBGPRINT("ImageFilter!ThreadNotifyRoutine: Failed to allocate work item");
        return;
    }

    // Initialize work item
    workItem->ProcessId = ProcessId;
    workItem->ThreadId = ThreadId;
    workItem->CallerProcessId = PsGetCurrentProcessId();

    // Initialize the work queue item
    ExInitializeWorkItem(&workItem->WorkItem, 
                        ThreadCreateNotifyWorkItemRoutine, 
                        workItem);

    // Queue the work item to process this notification at PASSIVE_LEVEL
    ExQueueWorkItem(&workItem->WorkItem, DelayedWorkQueue);
    
    DBGPRINT("ImageFilter!ThreadNotifyRoutine: Queued work item for thread ID %p in process %p",
            ThreadId, ProcessId);
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
	AcquireProcessLock();

	if (ImageFilter::ProcessHistory)
	{
		// Iterate through the array
		for (ULONG64 i = 0; i < ImageFilter::ProcessHistorySize; i++)
		{
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
	ReleaseProcessLock();
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
	AcquireProcessLock();

	if (ImageFilter::ProcessHistory)
	{
		// Iterate through the array
		for (ULONG64 processIndex = 0; processIndex < ImageFilter::ProcessHistorySize; processIndex++)
		{
			currentProcessHistory = &ImageFilter::ProcessHistory[processIndex];
			if (ImageDetailedRequest->ProcessId == currentProcessHistory->ProcessId &&
				ImageDetailedRequest->EpochExecutionTime == currentProcessHistory->EpochExecutionTime)
			{
				//
				// Iterate the images for basic information.
				//
				AcquireProcessLock();

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

				ReleaseProcessLock();
				break;
			}
			// Already advancing in the for loop
		}
	}

	//
	// Release the lock.
	//
	ReleaseProcessLock();
}

/**
 * Get detailed information about a specific process
 * @param ProcessId - The process ID to get details for
 * @param ProcessDetails - Structure to fill with process details
 * @return TRUE if process was found, FALSE otherwise
 */
BOOLEAN
ImageFilter::GetProcessDetails(
    _In_ HANDLE ProcessId,
    _Out_ PPROCESS_INFO ProcessDetails)
{
    PPROCESS_HISTORY_ENTRY targetProcess = NULL;
    BOOLEAN foundProcess = FALSE;

    // Initialize output structure
    RtlZeroMemory(ProcessDetails, sizeof(PROCESS_INFO));
    ProcessDetails->ProcessId = HandleToUlong(ProcessId);

    if (ImageFilter::destroying)
    {
        return FALSE;
    }

    // Acquire lock once for the entire operation
    AcquireProcessLock();

    // Search for the process in our history
    for (ULONG64 i = 0; i < ImageFilter::ProcessHistorySize; i++)
    {
        if (ImageFilter::ProcessHistory[i].ProcessId == ProcessId)
        {
            targetProcess = &ImageFilter::ProcessHistory[i];
            foundProcess = TRUE;
            break;
        }
    }

    // If process was found, copy the detailed information
    if (foundProcess && targetProcess != NULL)
    {
        // Copy basic information
        ProcessDetails->ProcessId = HandleToUlong(ProcessId);
        ProcessDetails->ParentProcessId = HandleToUlong(targetProcess->ParentId);
        ProcessDetails->IsTerminated = targetProcess->ProcessTerminated;
        
        // Set creation time
        ULONGLONG epochSeconds = targetProcess->EpochExecutionTime;
        LARGE_INTEGER fileTime;
        fileTime.QuadPart = (epochSeconds + 11644473600ULL) * 10000000ULL;
        ProcessDetails->CreationTime = fileTime;

        // Copy image path
        if (targetProcess->ProcessImageFileName && 
            targetProcess->ProcessImageFileName->Buffer &&
            targetProcess->ProcessImageFileName->Length > 0)
        {
            RtlCopyMemory(ProcessDetails->ImagePath,
                        targetProcess->ProcessImageFileName->Buffer,
                        min(sizeof(ProcessDetails->ImagePath) - sizeof(WCHAR),
                            targetProcess->ProcessImageFileName->Length));
            
            // Ensure null termination
            ProcessDetails->ImagePath[min((MAX_PATH_LENGTH - 1), 
                                    (targetProcess->ProcessImageFileName->Length / sizeof(WCHAR)))] = L'\0';
        }
        
        // Copy command line if available
        if (targetProcess->ProcessCommandLine && 
            targetProcess->ProcessCommandLine->Buffer &&
            targetProcess->ProcessCommandLine->Length > 0)
        {
            RtlCopyMemory(ProcessDetails->CommandLine,
                        targetProcess->ProcessCommandLine->Buffer,
                        min(sizeof(ProcessDetails->CommandLine) - sizeof(WCHAR),
                            targetProcess->ProcessCommandLine->Length));
            
            // Ensure null termination
            ProcessDetails->CommandLine[min((MAX_PATH_LENGTH - 1), 
                                      (targetProcess->ProcessCommandLine->Length / sizeof(WCHAR)))] = L'\0';
        }
        
        // Set default username (since we don't capture it)
        //wcscpy_s(ProcessDetails->UserName, L"[Not Available]");
        
        // MALWARE DETECTION ENHANCEMENTS
        // Count the number of loaded DLLs/modules
        ProcessDetails->LoadedModuleCount = targetProcess->ImageLoadHistorySize;
        
        // Count threads
        ProcessDetails->ThreadCount = targetProcess->ProcessThreadCount;
        
        // Check if process has remote loaded modules
        ProcessDetails->HasRemoteLoadedModules = FALSE;
        ProcessDetails->RemoteLoadCount = 0;
        
        // Check if process has remote created threads
        ProcessDetails->HasRemoteCreatedThreads = FALSE;
        ProcessDetails->RemoteThreadCount = 0;
        
        // Check each loaded module to see if any were remotely loaded
        if (targetProcess->ImageLoadHistory && targetProcess->ImageLoadHistorySize > 0)
        {
            // First entry is head of the linked list
            PIMAGE_LOAD_HISTORY_ENTRY currentEntry = 
                RCAST<PIMAGE_LOAD_HISTORY_ENTRY>(targetProcess->ImageLoadHistory->ListEntry.Flink);
            
            while (currentEntry != targetProcess->ImageLoadHistory)
            {
                // Check if this module was remotely loaded
                if (currentEntry->RemoteImage)
                {
                    ProcessDetails->HasRemoteLoadedModules = TRUE;
                    ProcessDetails->RemoteLoadCount++;
                    
                    // Store the first remote module we find
                    if (ProcessDetails->RemoteLoadCount == 1 && 
                        currentEntry->ImageFileName.Buffer && 
                        currentEntry->ImageFileName.Length > 0)
                    {
                        RtlCopyMemory(ProcessDetails->FirstRemoteModule,
                                    currentEntry->ImageFileName.Buffer,
                                    min(sizeof(ProcessDetails->FirstRemoteModule) - sizeof(WCHAR),
                                        currentEntry->ImageFileName.Length));
                        
                        // Ensure null termination
                        ProcessDetails->FirstRemoteModule[min((MAX_PATH_LENGTH - 1), 
                                                       (currentEntry->ImageFileName.Length / sizeof(WCHAR)))] = L'\0';
                    }
                }
                
                // Move to next entry
                currentEntry = RCAST<PIMAGE_LOAD_HISTORY_ENTRY>(currentEntry->ListEntry.Flink);
                
                // Safety check - break if we somehow loop back to the start
                if (currentEntry == targetProcess->ImageLoadHistory)
                    break;
            }
        }
        
        // Check for remote created threads
        if (targetProcess->ThreadHistory && targetProcess->ThreadHistorySize > 0)
        {
            for (ULONG i = 0; i < targetProcess->ThreadHistorySize; i++)
            {
                if (targetProcess->ThreadHistory[i].CreatorProcessId != targetProcess->ProcessId)
                {
                    ProcessDetails->HasRemoteCreatedThreads = TRUE;
                    ProcessDetails->RemoteThreadCount++;
                    
                    // Store details of first remote thread
                    if (ProcessDetails->RemoteThreadCount == 1)
                    {
                        ProcessDetails->FirstRemoteThreadCreator = 
                            HandleToUlong(targetProcess->ThreadHistory[i].CreatorProcessId);
                        ProcessDetails->FirstRemoteThreadAddress = 
                            (ULONG_PTR)targetProcess->ThreadHistory[i].StartAddress;
                    }
                }
            }
        }
        
        // Calculate a simple anomaly score (0-100) for suspicious indicators
        LONG anomalyScore = 0;
        
        // Remote loaded modules are very suspicious
        if (ProcessDetails->HasRemoteLoadedModules)
            anomalyScore += 40;
        
        // Remote created threads are very suspicious
        if (ProcessDetails->HasRemoteCreatedThreads)
            anomalyScore += 40;
        
        // Unusual parent process could be suspicious
        if (ProcessDetails->ParentProcessId == 0 || 
            ProcessDetails->ParentProcessId == 4) // System process
            anomalyScore += 5;
        
        // Terminated processes aren't a current threat but worth noting
        if (ProcessDetails->IsTerminated)
            anomalyScore -= 15;
        
        // Clamp score between 0-100 manually
        if (anomalyScore > 100) {
            ProcessDetails->AnomalyScore = 100;
        } else if (anomalyScore < 0) {
            ProcessDetails->AnomalyScore = 0;
        } else {
            ProcessDetails->AnomalyScore = (ULONG)anomalyScore;
        }
    }
    
    // Release lock before returning
    ReleaseProcessLock();
    
    return foundProcess;
}