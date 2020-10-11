#pragma once
class _KeHook {
public:
	PBYTE Create(UNICODE_STRING _Name, PBYTE _NTFunction, PBYTE _Function);

	VOID  Remove(UNICODE_STRING _Name);

	VOID  RemoveAll();

private:
	typedef struct _KeEntry {
		PBYTE Trampoline;
		PBYTE NTFunction;
		PBYTE Function;
		SIZE_T Size;
		UNICODE_STRING Name;
	} KeEntry, * PKeEntry;

	KeEntry Hooks[500];
	SIZE_T  HookCount = 0;


	BOOL IsNameExisting(UNICODE_STRING _Name);

	BOOL IsFunctionHooked(PBYTE _NTFunction);

	SIZE_T FindHookLength(PBYTE _NTFunction, SIZE_T _ShellCodeLength);
};

_KeHook KeHook;

PBYTE _KeHook::Create(UNICODE_STRING _Name, PBYTE _NTFunction, PBYTE _Function) {
	BYTE ShellCode[] = {
		0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,             // JMP + RIP
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // Absolute Address
	};

	// Check NTFunction, Or find by name.
	if (!_NTFunction) {
		_NTFunction = (PBYTE)MmGetSystemRoutineAddress(&_Name);
		if (!_NTFunction) {
			Utils::Print("[KeHook] [%ws] Failed To Find NT Function", _Name.Buffer);
			return 0;
		}
	}

	// Check if name is used.
	if (IsNameExisting(_Name)) {
		Utils::Print("[KeHook] [%ws] Name Already In Use", _Name.Buffer);
		return 0;
	}

	// Check if NT Function is hooked.
	if (IsFunctionHooked(_NTFunction)) {
		Utils::Print("[KeHook] [%ws] Function Already Hooked", _Name.Buffer);
		return 0;
	}

	// Find length needed on NTFunction
	SIZE_T HookLength = FindHookLength(_NTFunction, sizeof(ShellCode));

	// Create Trampoline
	PBYTE Trampoline = (PBYTE)ExAllocatePool(NonPagedPoolExecute, HookLength + sizeof(ShellCode));
	if (!Trampoline) {
		Utils::Print("[KeHook] [%ws] Failed Allocating Trampoline", _Name.Buffer);
		return 0;
	}

	// Copy NT Bytes On Trampoline
	if (!NT_SUCCESS(Utils::SuperCopyMemory(Trampoline, _NTFunction, HookLength))) {
		Utils::Print("[KeHook] [%ws] Failed Copying NT Bytes", _Name.Buffer);
		ExFreePoolWithTag(Trampoline, 0);
		return 0;
	}

	// Write JMP On Trampoline
	*(PBYTE*)&ShellCode[6] = _NTFunction + HookLength;
	if (!NT_SUCCESS(Utils::SuperCopyMemory(Trampoline + HookLength, &ShellCode[0], sizeof(ShellCode)))) {
		Utils::Print("[KeHook] [%ws] Failed Writing JMP On Trampoline", _Name.Buffer);
		ExFreePoolWithTag(Trampoline, 0);
		return 0;
	}


	// Write JMP On NTFunction
	*(PBYTE*)&ShellCode[6] = _Function;
	if (!NT_SUCCESS(Utils::SuperCopyMemory(_NTFunction, &ShellCode[0], sizeof(ShellCode)))) {
		Utils::Print("[KeHook] [%ws] Failed Writing JMP On NTFunction", _Name.Buffer);
		ExFreePoolWithTag(Trampoline, 0);
		return 0;
	}

	// NOP Left Over Bytes On NTFunction [Not Critical]
	if (sizeof(ShellCode) > HookLength) {
		if (!NT_SUCCESS(Utils::SuperCleanMemory(_NTFunction + sizeof(ShellCode), 0x90, HookLength - sizeof(ShellCode)))) {
			Utils::Print("[KeHook] [%ws] Failed NOP Left Over Bytes On NTFunction", _Name.Buffer);
		}
	}

	// Log
	Utils::Print("[KeHook] [%ws] Hook Placed", _Name.Buffer);

	KeEntry Entry;
	Entry.Name = _Name;
	Entry.Trampoline = Trampoline;
	Entry.NTFunction = _NTFunction;
	Entry.Function = _Function;
	Entry.Size = HookLength;
	Hooks[HookCount++] = Entry;

	return Trampoline;
}

VOID _KeHook::Remove(UNICODE_STRING _Name) {
	for (SIZE_T i = 0; i < HookCount; i++) {
		if (!Hooks[i].Name.Buffer || RtlCompareMemory(Hooks[i].Name.Buffer, _Name.Buffer, _Name.Length) != _Name.Length)
			continue;

		// Copy NT BytesFrom Trampoline Onto NTFunction
		if (!NT_SUCCESS(Utils::SuperCopyMemory(Hooks[i].NTFunction, Hooks[i].Trampoline, Hooks[i].Size))) {
			Utils::Print("[KeHook] [%ws] Failed Restoring NT Bytes", Hooks[i].Name.Buffer);
			break;
		}

		// Release Trampoline
		ExFreePoolWithTag(Hooks[i].Trampoline, 0);

		// Log
		Utils::Print("[KeHook] [%ws] Removed Hook", Hooks[i].Name.Buffer);

		// Clean
		RtlSecureZeroMemory(&Hooks[i], sizeof(KeEntry));

		break;
	}
}

VOID _KeHook::RemoveAll() {
	for (SIZE_T i = 0; i < HookCount; i++) {
		if (!Hooks[i].Name.Buffer)
			continue;

		Remove(Hooks[i].Name);
	}
}


BOOL _KeHook::IsNameExisting(UNICODE_STRING _Name) {
	for (SIZE_T i = 0; i < HookCount; i++) {
		if (!Hooks[i].Name.Buffer || RtlCompareMemory(Hooks[i].Name.Buffer, _Name.Buffer, _Name.Length) != _Name.Length) continue;
		return TRUE;
		break;
	}
	return FALSE;
}

BOOL _KeHook::IsFunctionHooked(PBYTE _NTFunction) {
	for (SIZE_T i = 0; i < HookCount; i++) {
		if (!Hooks[i].Name.Buffer || Hooks[i].NTFunction != _NTFunction) continue;
		return TRUE;
		break;
	}
	return FALSE;
}

SIZE_T _KeHook::FindHookLength(PBYTE _NTFunction, SIZE_T _ShellCodeLength) {
	SIZE_T Length = _ShellCodeLength;
	while (true) {
		if (*(BYTE*)(_NTFunction + Length) == 0x45) break; // MOV
		if (*(BYTE*)(_NTFunction + Length) == 0x48) break; // MOV
		if (*(BYTE*)(_NTFunction + Length) == 0xC3) break; // RTRN
		Length++;
	};
	return Length;
}

