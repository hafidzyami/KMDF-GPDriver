#include "pch.h"
#include "ImageFilter.h"

// Static DPC variables for deferred processing
static KDPC ImageNotificationDpc;
static BOOLEAN DpcInitialized = FALSE;
static PVOID DeferredImageName = NULL;
static HANDLE DeferredProcessId = NULL;
static PVOID DeferredImageInfo = NULL;

// DPC routine for deferred image processing
VOID
DeferredImageNotifyRoutine(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
)
{
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(DeferredContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);
    
    // Process at PASSIVE_LEVEL
    if (KeGetCurrentIrql() == PASSIVE_LEVEL) {
        if (DeferredImageName != NULL && DeferredProcessId != NULL) {
            // Process the image notification at PASSIVE_LEVEL
            ImageFilter::LoadImageNotifyRoutine((PUNICODE_STRING)DeferredImageName, 
                                               DeferredProcessId, 
                                               (PIMAGE_INFO)DeferredImageInfo);
            
            // Clear the deferred parameters
            DeferredImageName = NULL;
            DeferredProcessId = NULL;
            DeferredImageInfo = NULL;
        }
    }
}

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

// Rest of the code continues as-is...
