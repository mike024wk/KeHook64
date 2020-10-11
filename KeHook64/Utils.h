#pragma once
namespace Utils {
	VOID Print(PCHAR Message, ...);
	NTSTATUS SuperCopyMemory(PBYTE Dest, PBYTE Src, ULONG Length);
	NTSTATUS SuperCleanMemory(PBYTE Dest, BYTE Val, ULONG Length);
}

VOID Utils::Print(PCHAR Message, ...) {
	va_list(Arguments);
	va_start(Arguments, Message);
	vDbgPrintExWithPrefix("[xPaw] ", 0, 0, Message, Arguments);
	va_end(Arguments);
}

NTSTATUS Utils::SuperCopyMemory(PBYTE Dest, PBYTE Src, ULONG Length) {
	PMDL mdl = IoAllocateMdl(Dest, Length, 0, 0, 0);
	if (!mdl) return STATUS_UNSUCCESSFUL;

	MmBuildMdlForNonPagedPool(mdl);
	PBYTE Mapped = (PBYTE)MmMapLockedPages(mdl, KernelMode);
	if (!Mapped) {
		IoFreeMdl(mdl);
		return STATUS_UNSUCCESSFUL;
	}

	KIRQL kirql = KeRaiseIrqlToDpcLevel();
	memcpy(Mapped, Src, Length);
	KeLowerIrql(kirql);

	MmUnmapLockedPages(Mapped, mdl);
	IoFreeMdl(mdl);

	return STATUS_SUCCESS;
}

NTSTATUS Utils::SuperCleanMemory(PBYTE Dest, BYTE Val, ULONG Length) {
	PMDL mdl = IoAllocateMdl(Dest, Length, 0, 0, 0);
	if (!mdl) return STATUS_UNSUCCESSFUL;

	MmBuildMdlForNonPagedPool(mdl);
	PBYTE Mapped = (PBYTE)MmMapLockedPages(mdl, KernelMode);
	if (!Mapped) {
		IoFreeMdl(mdl);
		return STATUS_UNSUCCESSFUL;
	}

	KIRQL kirql = KeRaiseIrqlToDpcLevel();
	memset(Mapped, Val, Length);
	KeLowerIrql(kirql);

	MmUnmapLockedPages(Mapped, mdl);
	IoFreeMdl(mdl);

	return STATUS_SUCCESS;
}