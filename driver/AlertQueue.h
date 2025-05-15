/*
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE', which is part of this source code package.
 * 
 * COPYRIGHT Bill Demirkapi 2020
 */
#pragma once
#include "common.h"
#include "shared.h"
#include "IOCTLShared.h" // Include IOCTL shared structures

typedef class AlertQueue
{
	BASE_ALERT_INFO alertsHead; // The linked list of alerts.
	PKSPIN_LOCK alertsLock; // The lock protecting the linked-list of alerts.
	BOOLEAN destroying; // This boolean indicates to functions that a lock should not be held as we are in the process of destruction.

public:
	AlertQueue();
	~AlertQueue();

	VOID PushAlert (
		_In_ PBASE_ALERT_INFO Alert,
		_In_ ULONG AlertSize
		);

	PBASE_ALERT_INFO PopAlert (
		VOID
		);

	/**
	 * Pop multiple alerts from the queue
	 * @param AlertBuffer Buffer to store the alerts
	 * @param MaxAlerts Maximum number of alerts to retrieve
	 * @return Number of alerts retrieved
	 */
	ULONG PopMultipleAlerts (
		_Out_ PALERT_INFO AlertBuffer,
		_In_ ULONG MaxAlerts
		);

	/**
	 * Copy all alerts in the queue without removing them
	 * @param AlertCopies Array to store pointers to alerts
	 * @param MaxAlerts Maximum number of alerts to copy
	 * @return Number of alerts copied
	 */
	ULONG CopyAllAlerts (
		_Out_ PBASE_ALERT_INFO* AlertCopies,
		_In_ ULONG MaxAlerts
		);

	/**
	 * Get the number of alerts in the queue
	 * @return Count of alerts currently in the queue
	 */
	ULONG GetAlertCount (
		VOID
		);

	BOOLEAN IsQueueEmpty (
		VOID
		);

	VOID FreeAlert (
		_In_ PBASE_ALERT_INFO Alert
		);

} ALERT_QUEUE, *PALERT_QUEUE;

#define ALERT_LOCK_TAG 'lAmP'
#define ALERT_QUEUE_ENTRY_TAG 'eAmP'