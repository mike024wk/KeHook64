#include <ntifs.h>
#include <stdarg.h>
#include <windef.h>

#include "Utils.h"
#include "KeHook.h"

DRIVER_INITIALIZE DriverEntry;

#pragma region Example Hook
typedef BOOLEAN(*lpKeSetTimerEx)(PKTIMER Timer, LARGE_INTEGER DueTime, LONG Period, PKDPC Dpc);
PBYTE oKeSetTimerEx;

BOOLEAN HookedKeSetTimerEx(PKTIMER Timer, LARGE_INTEGER DueTime, LONG Period, PKDPC Dpc) {
	Utils::Print("Called 'KeSetTimerEx' From pID: %d", PsGetCurrentProcessId());
	return ((lpKeSetTimerEx)oKeSetTimerEx)(Timer, DueTime,Period, Dpc);
}
#pragma endregion

VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
	Utils::Print("Unload Started");

	KeHook.RemoveAll();

	Utils::Print("Unload Finished");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING DriverName) {

	Utils::Print("Load Started");

	// Example Hook
	oKeSetTimerEx = KeHook.Create(RTL_CONSTANT_STRING(L"KeSetTimerEx"), (PBYTE)KeSetTimerEx, (PBYTE)HookedKeSetTimerEx);

	Utils::Print("Load Finished");

	return STATUS_SUCCESS;
}