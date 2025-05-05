#include <windows.h>
#include <evntprov.h>  
#include <stdio.h>

#pragma comment(lib, "ntdll.lib")

typedef ULONG(WINAPI* pEtwEventWrite)(
	REGHANDLE RegHandle,
	PCEVENT_DESCRIPTOR EventDescriptor,
	ULONG UserDataCount,
	PEVENT_DATA_DESCRIPTOR UserData
	);

void* g_EtwEventWrite = nullptr;

ULONG WINAPI MyEtwEventWrite(
	REGHANDLE RegHandle,
	PCEVENT_DESCRIPTOR EventDescriptor,
	ULONG UserDataCount,
	PEVENT_DATA_DESCRIPTOR UserData
) {
	char buffer[512];

	sprintf_s(buffer, "EtwEventWrite called (hooked)\nRegHandle: %p\nUserDataCount: %lu\n",
		(void*)RegHandle, UserDataCount);
	OutputDebugStringA(buffer);

	// Print EventDescriptor fields (if not null)
	if (EventDescriptor) {
		sprintf_s(buffer,
			"EventDescriptor:\n  Id: %hu\n  Version: %hhu\n  Channel: %hhu\n"
			"  Level: %hhu\n  Opcode: %hhu\n  Task: %hu\n  Keyword: 0x%llx\n",
			EventDescriptor->Id, EventDescriptor->Version, EventDescriptor->Channel,
			EventDescriptor->Level, EventDescriptor->Opcode, EventDescriptor->Task,
			EventDescriptor->Keyword);
		OutputDebugStringA(buffer);
	}

	// Print each UserData entry
	for (ULONG i = 0; i < UserDataCount; ++i) {
		const void* ptr = (const void*)UserData[i].Ptr;
		ULONG size = UserData[i].Size;

		sprintf_s(buffer, "UserData[%lu]: Ptr = %p, Size = %lu\n", i, ptr, size);
		OutputDebugStringA(buffer);

		// Show hex dump (max 64 bytes)
		const ULONG maxDumpSize = 64;
		ULONG len = (size < maxDumpSize) ? size : maxDumpSize;

		char hexDump[3 * maxDumpSize + 1] = { 0 };
		char asciiDump[maxDumpSize + 1] = { 0 };

		for (ULONG j = 0; j < len; ++j) {
			BYTE byte = ((BYTE*)ptr)[j];
			sprintf_s(hexDump + j * 3, 4, "%02X ", byte); // hex
			asciiDump[j] = (byte >= 32 && byte <= 126) ? byte : '.'; // printable ASCII or dot
		}
		asciiDump[len] = '\0';

		OutputDebugStringA("Hex: ");
		OutputDebugStringA(hexDump);
		OutputDebugStringA("\nText: ");
		OutputDebugStringA(asciiDump);
		OutputDebugStringA("\n");
	}

	return 0; // You can call the original EtwEventWrite here if desired
}


void ForceEtwCall() {
	OutputDebugStringA("Calling EtwEventWrite manually to trigger hook...\n");

	EVENT_DESCRIPTOR desc;
	desc.Id = 0x01;
	desc.Version = 1;
	desc.Channel = 0;
	desc.Level = 4;       // Informational
	desc.Opcode = 0;
	desc.Task = 1;
	desc.Keyword = 0x1;

	// User data payload (a simple string message)
	const char* message = "Hello from EtwEventWrite!";
	EVENT_DATA_DESCRIPTOR data;
	EventDataDescCreate(&data, message, (ULONG)(strlen(message) + 1)); // Include null terminator

	// Resolve EtwEventWrite function
	pEtwEventWrite EtwFunc = (pEtwEventWrite)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "EtwEventWrite");
	if (EtwFunc) {
		EtwFunc((REGHANDLE)1, &desc, 1, &data);  // (REGHANDLE)1 is a dummy handle
	}
}


LONG WINAPI VectoredHandler(PEXCEPTION_POINTERS ExceptionInfo) {
	if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION) {
		if ((void*)ExceptionInfo->ContextRecord->Rip == g_EtwEventWrite) {
			ExceptionInfo->ContextRecord->Rip = (DWORD64)&MyEtwEventWrite;

			DWORD oldProtect;
			VirtualProtect(g_EtwEventWrite, 1, PAGE_EXECUTE_READ | PAGE_GUARD, &oldProtect);
			return EXCEPTION_CONTINUE_EXECUTION;
		}
	}
	return EXCEPTION_CONTINUE_SEARCH;
}

void SetupHook() {
	HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
	g_EtwEventWrite = GetProcAddress(hNtdll, "EtwEventWrite");

	DWORD oldProtect;
	VirtualProtect(g_EtwEventWrite, 1, PAGE_EXECUTE_READ | PAGE_GUARD, &oldProtect);

	AddVectoredExceptionHandler(1, VectoredHandler);
	OutputDebugStringA("Hook installed.\n");

	ForceEtwCall();
}

// Entry point de la DLL
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
	if (fdwReason == DLL_PROCESS_ATTACH) {
		DisableThreadLibraryCalls(hinstDLL);
		SetupHook();
	}
	return TRUE;
}
