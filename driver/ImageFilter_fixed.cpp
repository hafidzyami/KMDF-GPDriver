#include "pch.h"
#include "ImageFilter.h"

// Work item structure for deferred image load processing
typedef struct _IMAGE_LOAD_WORK_ITEM {
	WORK_QUEUE_ITEM WorkItem;
	UNICODE_STRING ImageName;
	HANDLE ProcessId;
	IMAGE_INFO ImageInfo;
} IMAGE_LOAD_WORK_ITEM, *PIMAGE_LOAD_WORK_ITEM;

// Work item routine for deferred image processing
VOID ImageLoadWorkItemRoutine(
	_In_ PVOID Context
)
{
	PIMAGE_LOAD_WORK_ITEM workItem = (PIMAGE_LOAD_WORK_ITEM)Context;
	
	if (workItem != NULL)
	{
		// Now we're at PASSIVE_LEVEL, safe to process the image load
		PUNICODE_STRING imageNamePtr = NULL;
		
		// Only pass the image name if it's valid
		if (workItem->ImageName.Buffer != NULL && workItem->ImageName.Length > 0)
		{
			imageNamePtr = &workItem->ImageName;
		}

		// Process the image notification at PASSIVE_LEVEL
		ImageFilter::LoadImageNotifyRoutine(
			imageNamePtr,
			workItem->ProcessId,
			&workItem->ImageInfo);

		// Free the image name buffer if it was allocated
		if (workItem->ImageName.Buffer != NULL)
		{
			ExFreePoolWithTag(workItem->ImageName.Buffer, 'ILwI');
		}
		
		// Free the work item
		ExFreePoolWithTag(workItem, 'ILwI');
	}
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
	ImageFilter::ProcessHistory =