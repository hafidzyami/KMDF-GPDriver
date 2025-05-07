/*
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE', which is part of this source code package.
 * 
 * COPYRIGHT Bill Demirkapi 2020
 */
#include "pch.h"
#include "AlertQueue.h"

/**
	Initialize basic members of the AlertQueue class.
*/
AlertQueue::AlertQueue()
{
	this->alertsLock = RCAST<PKSPIN_LOCK>(ExAllocatePool2(POOL_FLAG_NON_PAGED_EXECUTE, sizeof(KSPIN_LOCK), ALERT_LOCK_TAG));
	NT_ASSERT(this->alertsLock);
	this->destroying = FALSE;
	KeInitializeSpinLock(this->alertsLock);
	InitializeListHead(RCAST<PLIST_ENTRY>(&this->alertsHead));
}

/**
	Clear the queue of alerts.
*/
AlertQueue::~AlertQueue()
{
	PLIST_ENTRY currentEntry;
	KIRQL oldIRQL;

	//
	// Make sure no one is doing operations on the AlertQueue.
	//
	this->destroying = TRUE;

	KeAcquireSpinLock(this->alertsLock, &oldIRQL);
	KeReleaseSpinLock(this->alertsLock, oldIRQL);

	while (IsListEmpty(RCAST<PLIST_ENTRY>(&this->alertsHead)) == FALSE)
	{
		currentEntry = RemoveHeadList(RCAST<PLIST_ENTRY>(&this->alertsHead));
		//
		// Free the entry.
		//
		ExFreePoolWithTag(SCAST<PVOID>(currentEntry), ALERT_QUEUE_ENTRY_TAG);
	}

	ExFreePoolWithTag(this->alertsLock, ALERT_LOCK_TAG);
}

/**
	Push an alert to the queue.
	@param Alert - The alert to push.
	@return Whether or not pushing the alert was successful.
*/
VOID
AlertQueue::PushAlert (
	_In_ PBASE_ALERT_INFO Alert,
	_In_ ULONG AlertSize
	)
{
	PBASE_ALERT_INFO newAlert;

	if (this->destroying)
	{
		return;
	}

	//
	// Allocate space for the new alert and copy the details.
	//
	newAlert = RCAST<PBASE_ALERT_INFO>(ExAllocatePool2(POOL_FLAG_NON_PAGED_EXECUTE, AlertSize, ALERT_QUEUE_ENTRY_TAG));
	if (newAlert == NULL)
	{
		DBGPRINT("AlertQueue!PushAlert: Failed to allocate space for new alert.");
		return;
	}
	memset(newAlert, 0, AlertSize);
	memcpy(newAlert, Alert, AlertSize);
	newAlert->AlertSize = AlertSize;

	//
	// Queue the alert.
	//
	ExInterlockedInsertTailList(RCAST<PLIST_ENTRY>(&this->alertsHead), RCAST<PLIST_ENTRY>(newAlert), this->alertsLock);
}

/**
	Pop an alert from the queue of alerts. Follows FI-FO.
	@return The first in queued alert.
*/
PBASE_ALERT_INFO
AlertQueue::PopAlert (
	VOID
	)
{
	if (this->destroying)
	{
		return NULL;
	}
	return RCAST<PBASE_ALERT_INFO>(ExInterlockedRemoveHeadList(RCAST<PLIST_ENTRY>(&this->alertsHead), this->alertsLock));
}

/**
	Check if the queue of alerts is empty.
	@return Whether or not the alerts queue is empty.
*/
BOOLEAN
AlertQueue::IsQueueEmpty (
	VOID
	)
{
	BOOLEAN empty;
	KIRQL oldIrql;

	ExAcquireSpinLock(this->alertsLock, &oldIrql);
	empty = IsListEmpty(RCAST<PLIST_ENTRY>(&this->alertsHead));
	ExReleaseSpinLock(this->alertsLock, oldIrql);

	return empty;
}

/**
 * Pop multiple alerts from the queue
 * @param AlertBuffer Buffer to store the alerts
 * @param MaxAlerts Maximum number of alerts to retrieve
 * @return Number of alerts retrieved
 */
ULONG
AlertQueue::PopMultipleAlerts(
	_Out_ PALERT_INFO AlertBuffer,
	_In_ ULONG MaxAlerts
	)
{
	if (this->destroying || AlertBuffer == NULL || MaxAlerts == 0)
	{
		return 0;
	}

	ULONG alertCount = 0;
	PBASE_ALERT_INFO baseAlert;
	KIRQL oldIrql;

	// Acquire the lock once to check if we have any alerts
	ExAcquireSpinLock(this->alertsLock, &oldIrql);
	BOOLEAN isEmpty = IsListEmpty(RCAST<PLIST_ENTRY>(&this->alertsHead));
	ExReleaseSpinLock(this->alertsLock, oldIrql);

	// Process as many alerts as we can, up to MaxAlerts
	while (!isEmpty && alertCount < MaxAlerts)
	{
		// Pop an alert from the queue
		baseAlert = this->PopAlert();
		if (baseAlert == NULL)
		{
			// No more alerts
			break;
		}

		// Treat baseAlert as EXTENDED_BASE_ALERT_INFO for proper field access
		// We'll work directly with baseAlert instead of converting to EXTENDED_BASE_ALERT_INFO

		// Convert BASE_ALERT_INFO to ALERT_INFO structure for user mode
		PALERT_INFO currentAlert = &AlertBuffer[alertCount];

		// Fill in the alert info from the extended base alert
		currentAlert->AlertId = alertCount + 1; // Assign incremental IDs
		currentAlert->Type = (ALERT_TYPE)baseAlert->AlertType; // Use AlertType from BASE_ALERT_INFO
		currentAlert->SourceProcessId = HandleToUlong(baseAlert->SourceId); // Use SourceId from BASE_ALERT_INFO
		currentAlert->TargetProcessId = 0; // Default value
		
		// Set timestamp to current time if not available
		LARGE_INTEGER currentTime;
		KeQuerySystemTime(&currentTime);
		currentAlert->Timestamp = currentTime;
		
		// Default value for violating address
		currentAlert->ViolatingAddress = 0;

		// Copy strings with proper bounds checking
		if (baseAlert->SourcePath[0] != L'\0') {
			RtlCopyMemory(currentAlert->SourcePath, 
					  baseAlert->SourcePath, 
					  min(sizeof(currentAlert->SourcePath), sizeof(baseAlert->SourcePath)));
		}

		if (baseAlert->TargetPath[0] != L'\0') {
			RtlCopyMemory(currentAlert->TargetPath, 
					  baseAlert->TargetPath, 
					  min(sizeof(currentAlert->TargetPath), sizeof(baseAlert->TargetPath)));
		}

		// Free the base alert as we've copied it to the output buffer
		this->FreeAlert(baseAlert);

		// Increment our count
		alertCount++;

		// Check if there are more alerts
		ExAcquireSpinLock(this->alertsLock, &oldIrql);
		isEmpty = IsListEmpty(RCAST<PLIST_ENTRY>(&this->alertsHead));
		ExReleaseSpinLock(this->alertsLock, oldIrql);
	}

	return alertCount;
}


/**
	Free a previously pop'd alert.
	@param Alert - The alert to free.
*/
VOID
AlertQueue::FreeAlert(
	_In_ PBASE_ALERT_INFO Alert
	)
{
	ExFreePoolWithTag(Alert, ALERT_QUEUE_ENTRY_TAG);
}