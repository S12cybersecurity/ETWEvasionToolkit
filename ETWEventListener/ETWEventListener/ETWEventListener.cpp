// etw_listen.cpp
// Single-file ETW consumer: enumerate providers, subscribe (enable), and listen/print events.
// Notes:
//  - Requires Windows, admin privileges often recommended.
//  - Enabling too many providers can produce a LOT of events; we cap how many to enable.
//  - This consumer does NOT write/emit events—only listens and prints.
//
// Build example (MSVC):
//   cl /EHsc etw_listen.cpp /link advapi32.lib tdh.lib

#define UNICODE
#define _UNICODE

#include <windows.h>
#include <evntrace.h>   // StartTrace/EnableTraceEx2/OpenTrace/ProcessTrace
#include <evntcons.h>   // PEVENT_RECORD
#include <tdh.h>        // TdhEnumerateProviders
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <vector>
#include <string>
#include <thread>
#include <atomic>
#include <iostream>
#include <iomanip>
#include <algorithm>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "tdh.lib")

struct ProviderInfo {
    GUID guid{};
    std::wstring name;
};

static std::wstring GuidToString(const GUID& g) {
    wchar_t buf[64];
    swprintf_s(buf, L"{%08lX-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX}",
        g.Data1, g.Data2, g.Data3,
        (unsigned char)g.Data4[0], (unsigned char)g.Data4[1],
        (unsigned char)g.Data4[2], (unsigned char)g.Data4[3],
        (unsigned char)g.Data4[4], (unsigned char)g.Data4[5],
        (unsigned char)g.Data4[6], (unsigned char)g.Data4[7]);
    return buf;
}

class ETWListener {
public:
    ETWListener()
        : sessionHandle_(0),
        hTrace_(INVALID_PROCESSTRACE_HANDLE),
        sessionName_(L"ETWListenerSession") {
    }

    ~ETWListener() {
        Stop();
    }

    // Enumerate all ETW providers installed on the system
    bool EnumerateProviders() {
        ULONG bufferSize = 0;
        PROVIDER_ENUMERATION_INFO* pInfo = nullptr;

        ULONG status = TdhEnumerateProviders(nullptr, &bufferSize);
        if (status != ERROR_INSUFFICIENT_BUFFER) {
            std::wcerr << L"TdhEnumerateProviders (size) failed: " << status << L"\n";
            return false;
        }

        pInfo = (PROVIDER_ENUMERATION_INFO*)malloc(bufferSize);
        if (!pInfo) {
            std::wcerr << L"Memory allocation failed for provider list.\n";
            return false;
        }

        status = TdhEnumerateProviders(pInfo, &bufferSize);
        if (status != ERROR_SUCCESS) {
            std::wcerr << L"TdhEnumerateProviders failed: " << status << L"\n";
            free(pInfo);
            return false;
        }

        providers_.clear();
        providers_.reserve(pInfo->NumberOfProviders);

        for (ULONG i = 0; i < pInfo->NumberOfProviders; ++i) {
            TRACE_PROVIDER_INFO& tpi = pInfo->TraceProviderInfoArray[i];
            ProviderInfo pi;
            pi.guid = tpi.ProviderGuid;
            if (tpi.ProviderNameOffset != 0) {
                pi.name = (LPCWSTR)((PBYTE)pInfo + tpi.ProviderNameOffset);
            }
            else {
                pi.name = L"Unknown";
            }
            providers_.push_back(std::move(pi));
        }

        std::wcout << L"Discovered " << providers_.size() << L" ETW providers.\n";
        free(pInfo);
        return true;
    }

    // Start a real-time session and enable up to maxToEnable providers (TRACE_LEVEL_VERBOSE, all keywords)
    bool Start(size_t maxToEnable = 16) {
        if (providers_.empty()) {
            std::wcerr << L"No providers enumerated. Call EnumerateProviders() first.\n";
            return false;
        }
        if (sessionHandle_ != 0 || hTrace_ != INVALID_PROCESSTRACE_HANDLE) {
            std::wcerr << L"Session already running.\n";
            return false;
        }

        // Prepare session properties buffer
        const ULONG nameChars = 256;
        const ULONG propsSize = sizeof(EVENT_TRACE_PROPERTIES) + nameChars * sizeof(wchar_t);
        EVENT_TRACE_PROPERTIES* props = (EVENT_TRACE_PROPERTIES*)malloc(propsSize);
        if (!props) {
            std::wcerr << L"Failed to allocate EVENT_TRACE_PROPERTIES.\n";
            return false;
        }
        ZeroMemory(props, propsSize);
        props->Wnode.BufferSize = propsSize;
        props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        props->Wnode.ClientContext = 2; // 2 = system time, so timestamps convert nicely
        props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

        // Set logger name
        wchar_t* loggerName = (wchar_t*)((BYTE*)props + props->LoggerNameOffset);
        wcsncpy_s(loggerName, nameChars, sessionName_.c_str(), _TRUNCATE);

        ULONG status = StartTraceW(&sessionHandle_, sessionName_.c_str(), props);
        free(props);
        if (status != ERROR_SUCCESS) {
            std::wcerr << L"StartTrace failed: " << status << L"\n";
            sessionHandle_ = 0;
            return false;
        }

        // Enable a subset of providers to avoid overwhelming output
        const ULONGLONG KEYWORD_ANY = 0xFFFFFFFFFFFFFFFFULL; // all keywords
        const ULONGLONG KEYWORD_ALL = 0;
        const UCHAR LEVEL = TRACE_LEVEL_VERBOSE;

        size_t enabled = 0;
        for (size_t i = 0; i < providers_.size() && enabled < maxToEnable; ++i) {
            const GUID& g = providers_[i].guid;
            status = EnableTraceEx2(
                sessionHandle_,
                &g,
                EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                LEVEL,
                KEYWORD_ANY,
                KEYWORD_ALL,
                0,
                nullptr
            );
            if (status == ERROR_SUCCESS) {
                ++enabled;
                std::wcout << L"Enabled: " << providers_[i].name << L" " << GuidToString(g) << L"\n";
            }
            else {
                // Many providers require specific keywords/levels or permissions; ignore failures.
            }
        }

        if (enabled == 0) {
            std::wcerr << L"Warning: no providers were enabled (permission/keyword/level mismatch?).\n";
        }

        // Open the real-time session for processing
        EVENT_TRACE_LOGFILEW logFile{};
        logFile.LoggerName = const_cast<LPWSTR>(sessionName_.c_str());
        logFile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        logFile.EventRecordCallback = &ETWListener::StaticEventRecordCallback;
        logFile.Context = this; // will show up as pEventRecord->UserContext

        hTrace_ = OpenTraceW(&logFile);
        if (hTrace_ == INVALID_PROCESSTRACE_HANDLE) {
            std::wcerr << L"OpenTrace failed.\n";
            StopTraceW(sessionHandle_, sessionName_.c_str(), nullptr);
            sessionHandle_ = 0;
            return false;
        }

        // Start processing in a background thread
        processingThread_ = std::thread([this]() {
            TRACEHANDLE handles[1] = { hTrace_ };
            ProcessTrace(handles, 1, nullptr, nullptr);
            CloseTrace(hTrace_);
            hTrace_ = INVALID_PROCESSTRACE_HANDLE;
            });

        std::wcout << L"Listening... (press ENTER to stop)\n";
        return true;
    }

    // Stop session and wait for processing to drain
    void Stop() {
        if (sessionHandle_ != 0) {
            StopTraceW(sessionHandle_, sessionName_.c_str(), nullptr);
            sessionHandle_ = 0;
        }
        if (processingThread_.joinable()) {
            processingThread_.join();
        }
    }

private:
    static VOID WINAPI StaticEventRecordCallback(PEVENT_RECORD pEventRecord) {
        if (!pEventRecord) return;
        ETWListener* self = reinterpret_cast<ETWListener*>(pEventRecord->UserContext);
        if (self) self->OnEventRecord(pEventRecord);
    }

    // Print every received event (basic header + first bytes of payload)
    void OnEventRecord(PEVENT_RECORD p) {
        const GUID& prov = p->EventHeader.ProviderId;

        // Convert timestamp (FILETIME since we set ClientContext=2)
        FILETIME ft{};
        ft.dwLowDateTime = (DWORD)(p->EventHeader.TimeStamp.QuadPart & 0xFFFFFFFF);
        ft.dwHighDateTime = (DWORD)(p->EventHeader.TimeStamp.QuadPart >> 32);
        SYSTEMTIME st{};
        FileTimeToSystemTime(&ft, &st);

        std::wstring providerName = LookupProviderName(prov);

        std::wcout << L"------------------------------------------------------------\n";
        std::wcout << L"Time     : "
            << std::setfill(L'0')
            << std::setw(4) << st.wYear << L"-"
            << std::setw(2) << st.wMonth << L"-"
            << std::setw(2) << st.wDay << L" "
            << std::setw(2) << st.wHour << L":"
            << std::setw(2) << st.wMinute << L":"
            << std::setw(2) << st.wSecond << L"."
            << std::setw(3) << st.wMilliseconds << L"\n";

        std::wcout << L"Provider : " << providerName << L" " << GuidToString(prov) << L"\n";
        std::wcout << L"Event Id : " << p->EventHeader.EventDescriptor.Id
            << L"  Level: " << (unsigned)p->EventHeader.EventDescriptor.Level
            << L"  Opcode: " << (unsigned)p->EventHeader.EventDescriptor.Opcode << L"\n";
        std::wcout << L"PID/TID  : " << p->EventHeader.ProcessId << L"/" << p->EventHeader.ThreadId << L"\n";
        std::wcout << L"Version  : " << (unsigned)p->EventHeader.EventDescriptor.Version
            << L"  Channel: " << (unsigned)p->EventHeader.EventDescriptor.Channel << L"\n";

        // Print first N bytes of payload in hex (if any)
        const USHORT len = p->UserDataLength;
        const BYTE* data = reinterpret_cast<const BYTE*>(p->UserData);
        const size_t MAX_HEX = 64; // adjust if you want more/less
        std::wcout << L"DataLen  : " << len << L"\n";
        if (data && len > 0) {
            std::wcout << L"DataHex  : ";
            const size_t show = (std::min)(static_cast<size_t>(len), MAX_HEX);
            for (size_t i = 0; i < show; ++i) {
                std::wcout << std::hex << std::uppercase
                    << std::setw(2) << std::setfill(L'0')
                    << (unsigned)data[i] << L" ";
            }
            std::wcout << std::dec << L"\n";
            if (len > show) {
                std::wcout << L"           ... (" << (len - show) << L" more bytes)\n";
            }
        }
        else {
            std::wcout << L"DataHex  : (none)\n";
        }
    }

    std::wstring LookupProviderName(const GUID& g) const {
        auto it = std::find_if(providers_.begin(), providers_.end(),
            [&g](const ProviderInfo& pi) { return IsEqualGUID(pi.guid, g); });
        return (it != providers_.end()) ? it->name : L"(Unknown)";
    }

private:
    std::vector<ProviderInfo> providers_;
    TRACEHANDLE               sessionHandle_;
    TRACEHANDLE               hTrace_;
    std::thread               processingThread_;
    std::wstring              sessionName_;
};

int wmain() {
    // 1) Enumerate providers
    ETWListener listener;
    if (!listener.EnumerateProviders()) {
        std::wcerr << L"Failed to enumerate providers.\n";
        return 1;
    }

    // 2) Start session + subscribe/enable (cap to avoid overwhelming the console)
    const size_t MAX_PROVIDERS_TO_ENABLE = 16; // adjust as needed
    if (!listener.Start(MAX_PROVIDERS_TO_ENABLE)) {
        std::wcerr << L"Failed to start ETW listener.\n";
        return 1;
    }

    // 3) Wait for user to stop
    (void)getchar();

    // 4) Stop session and exit
    listener.Stop();
    std::wcout << L"Stopped.\n";
    return 0;
}
