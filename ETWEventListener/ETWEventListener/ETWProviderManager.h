#include <windows.h>
#include <tdh.h>
#include <evntprov.h>
#include <iostream>
#include <algorithm>
#include <vector>
#include <thread>
#include <atomic>
#include <mutex>
#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "advapi32.lib")

// Struct to store basic provider information
struct ProviderInfo {
    GUID guid;
    std::wstring name;
    std::wstring description;
};

struct CapturedEvent {
    GUID providerId;
    std::wstring providerName;
    USHORT eventId;
    UCHAR level;
    ULONGLONG timestamp;
    std::wstring eventData;
    ULONG processId;
    ULONG threadId;
};

// Class to manage ETW providers
class ETWProviderManager {
private:
    std::vector<ProviderInfo> availableProviders; // List of all discovered ETW providers
    std::vector<REGHANDLE> registeredHandles;     // Handles of registered providers
    std::vector<CapturedEvent> eventBuffer;       // Buffer to store captured events
    std::mutex eventBufferMutex;                  // Mutex for thread-safe access to event buffer
    std::atomic<bool> isCapturing;                // Flag to control event capture
    std::thread captureThread;                    // Thread for event capture
    TRACEHANDLE sessionHandle;                    // Handle for ETW session
    static constexpr int EVENT_BATCH_SIZE = 20;   // Process events in batches of 20

    static VOID WINAPI EventRecordCallback(PEVENT_RECORD pEventRecord) {
        ETWProviderManager* manager = static_cast<ETWProviderManager*>(pEventRecord->UserContext);
        if (manager) {
            manager->ProcessEventRecord(pEventRecord);
        }
    }

    void ProcessEventRecord(PEVENT_RECORD pEventRecord) {
        CapturedEvent event;
        event.providerId = pEventRecord->EventHeader.ProviderId;
        event.eventId = pEventRecord->EventHeader.EventDescriptor.Id;
        event.level = pEventRecord->EventHeader.EventDescriptor.Level;
        event.timestamp = pEventRecord->EventHeader.TimeStamp.QuadPart;
        event.processId = pEventRecord->EventHeader.ProcessId;
        event.threadId = pEventRecord->EventHeader.ThreadId;

        // Find provider name
        event.providerName = L"Unknown";
        for (const auto& provider : availableProviders) {
            if (IsEqualGUID(provider.guid, event.providerId)) {
                event.providerName = provider.name;
                break;
            }
        }

        // Extract event data (simplified - could be expanded for more detailed parsing)
        if (pEventRecord->UserDataLength > 0) {
            // Convert binary data to hex string for display
            char* userData = static_cast<char*>(pEventRecord->UserData);
            std::wstring hexData;
            for (USHORT i = 0; i < min(pEventRecord->UserDataLength, (USHORT)64); i++) {
                wchar_t hex[4];
                swprintf_s(hex, L"%02X ", (unsigned char)userData[i]);
                hexData += hex;
            }
            event.eventData = hexData;
        }

        // Add event to buffer
        {
            std::lock_guard<std::mutex> lock(eventBufferMutex);
            eventBuffer.push_back(event);

            // Process batch when we have enough events
            if (eventBuffer.size() >= EVENT_BATCH_SIZE) {
                ProcessEventBatch();
                eventBuffer.clear();
            }
        }
    }

    // Process a batch of events and display information about the first 10
    void ProcessEventBatch() {
        std::cout << "\n=== Processing Event Batch ===\n";
        std::cout << "Total events in batch: " << eventBuffer.size() << "\n";
        std::cout << "Showing details for first 10 events:\n\n";

        int displayCount = min((int)eventBuffer.size(), 10);
        for (int i = 0; i < displayCount; i++) {
            const auto& event = eventBuffer[i];

            std::cout << "Event " << (i + 1) << ":\n";
            std::wcout << L"  Provider: " << event.providerName << L"\n";
            std::cout << "  Event ID: " << event.eventId << "\n";
            std::cout << "  Level: " << (int)event.level << "\n";
            std::cout << "  Process ID: " << event.processId << "\n";
            std::cout << "  Thread ID: " << event.threadId << "\n";
            std::cout << "  Timestamp: " << event.timestamp << "\n";
            std::wcout << L"  Data (hex): " << event.eventData << L"\n";
            std::cout << "\n";
        }

        if (eventBuffer.size() > 10) {
            std::cout << "... and " << (eventBuffer.size() - 10) << " more events in this batch.\n";
        }
        std::cout << "================================\n\n";
    }

public:
    ETWProviderManager() : isCapturing(false), sessionHandle(0) {}

    // Enumerate all ETW providers in the system
    bool EnumerateSystemProviders() {
        ULONG bufferSize = 0;
        PROVIDER_ENUMERATION_INFO* pProviders = nullptr;

        // First call to get required buffer size
        ULONG status = TdhEnumerateProviders(pProviders, &bufferSize);
        if (status != ERROR_INSUFFICIENT_BUFFER) {
            printf("TdhEnumerateProviders failed: %lu\n", status);
            return false;
        }

        // Allocate memory for providers
        pProviders = (PROVIDER_ENUMERATION_INFO*)malloc(bufferSize);
        if (!pProviders) {
            printf("Memory allocation failed\n");
            return false;
        }

        // Second call to actually get provider data
        status = TdhEnumerateProviders(pProviders, &bufferSize);
        if (status != ERROR_SUCCESS) {
            printf("TdhEnumerateProviders failed: %lu\n", status);
            free(pProviders);
            return false;
        }

        printf("Found %lu ETW providers in the system:\n\n", pProviders->NumberOfProviders);

        // Process each provider
        for (ULONG i = 0; i < pProviders->NumberOfProviders; i++) {
            TRACE_PROVIDER_INFO& provider = pProviders->TraceProviderInfoArray[i];

            ProviderInfo info;
            info.guid = provider.ProviderGuid;

            // Get provider name
            if (provider.ProviderNameOffset != 0) {
                info.name = (LPWSTR)((PBYTE)pProviders + provider.ProviderNameOffset);
            }
            else {
                info.name = L"Unknown";
            }

            availableProviders.push_back(info);

            // Print provider information
            printf("Provider %lu:\n", i + 1);
            printf("  GUID: {%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}\n",
                info.guid.Data1, info.guid.Data2, info.guid.Data3,
                info.guid.Data4[0], info.guid.Data4[1], info.guid.Data4[2], info.guid.Data4[3],
                info.guid.Data4[4], info.guid.Data4[5], info.guid.Data4[6], info.guid.Data4[7]);
            printf("  Name: %ls\n", info.name.c_str());

            // Only show the first 20 providers to avoid console clutter
            if (i >= 19) {
                printf("  ... and %lu more providers\n", pProviders->NumberOfProviders - 20);
                break;
            }
            printf("\n");
        }

        free(pProviders);
        return true;
    }

    // Register with popular ETW providers using their GUIDs
    bool RegisterAsPopularProviders(int maxProviders = 10) {
        printf("Attempting to register using existing popular provider GUIDs...\n\n");

        int registered = 0;
        for (size_t i = 0; i < availableProviders.size() && registered < maxProviders; i++) {
            const auto& provider = availableProviders[i];

            // Filter for providers with "important" names
            std::wstring lowerName = provider.name;
            std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::towlower);

               bool isImportant = lowerName.find(L"security") != std::wstring::npos ||
                   lowerName.find(L"antivirus") != std::wstring::npos ||
                   lowerName.find(L"defender") != std::wstring::npos ||
                   lowerName.find(L"sysmon") != std::wstring::npos ||
                   lowerName.find(L"endpoint") != std::wstring::npos;
            //bool isImportant = true;
            if (isImportant) {
                REGHANDLE handle;
                ULONG result = EventRegister(&provider.guid, nullptr, nullptr, &handle);

                if (result == ERROR_SUCCESS) {
                    registeredHandles.push_back(handle);
                    printf("Successfully registered as: %ls\n", provider.name.c_str());
                    printf("   GUID: {%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}\n",
                        provider.guid.Data1, provider.guid.Data2, provider.guid.Data3,
                        provider.guid.Data4[0], provider.guid.Data4[1], provider.guid.Data4[2], provider.guid.Data4[3],
                        provider.guid.Data4[4], provider.guid.Data4[5], provider.guid.Data4[6], provider.guid.Data4[7]);
                    registered++;
                }
                else {
                    printf("Failed to register as: %ls (Error: %lu)\n", provider.name.c_str(), result);
                }
                printf("\n");
            }
        }

        printf("Successfully registered with %d popular provider GUIDs\n", registered);
        return registered > 0;
    }

    bool StartEventCapture() {
        if (isCapturing || registeredHandles.empty()) {
            printf("Cannot start capture: %s\n",
                isCapturing ? "Already capturing" : "No providers registered");
            return false;
        }

        printf("Starting event capture for registered providers...\n");

        // Create ETW session
        EVENT_TRACE_PROPERTIES* sessionProps = nullptr;
        ULONG sessionPropsSize = sizeof(EVENT_TRACE_PROPERTIES) + (256 * sizeof(wchar_t));
        sessionProps = (EVENT_TRACE_PROPERTIES*)malloc(sessionPropsSize);

        if (!sessionProps) {
            printf("Failed to allocate memory for session properties\n");
            return false;
        }

        ZeroMemory(sessionProps, sessionPropsSize);
        sessionProps->Wnode.BufferSize = sessionPropsSize;
        sessionProps->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        sessionProps->Wnode.ClientContext = 1; // Use performance counter for timestamps
        sessionProps->Wnode.Guid = { 0 }; // Will be set by system
        sessionProps->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        sessionProps->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

        // Set session name
        wcscpy_s((wchar_t*)((char*)sessionProps + sessionProps->LoggerNameOffset),
            256, L"MyETWCaptureSession");

        // Start trace session
        ULONG result = StartTrace(&sessionHandle, L"MyETWCaptureSession", sessionProps);
        free(sessionProps);

        if (result != ERROR_SUCCESS) {
            printf("Failed to start trace session: %lu\n", result);
            return false;
        }

        // Enable providers in the session
        for (size_t i = 0; i < availableProviders.size() && i < registeredHandles.size(); i++) {
            EnableTraceEx2(sessionHandle, &availableProviders[i].guid, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                TRACE_LEVEL_VERBOSE, 0, 0, 0, nullptr);
        }

        // Set up event processing
        EVENT_TRACE_LOGFILE traceLogfile = { 0 };
        //const wchar_t* name = L"MyETWCaptureSession";
        wchar_t name[] = L"MyETWCaptureSession";
        traceLogfile.LoggerName = name;
        traceLogfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        traceLogfile.EventRecordCallback = EventRecordCallback;
        traceLogfile.Context = this;

        TRACEHANDLE traceHandle = OpenTrace(&traceLogfile);
        if (traceHandle == INVALID_PROCESSTRACE_HANDLE) {
            printf("Failed to open trace for processing\n");
            StopTrace(sessionHandle, L"MyETWCaptureSession", nullptr);
            return false;
        }

        PROCESSTRACE_HANDLE procTraceHandle = static_cast<PROCESSTRACE_HANDLE>(traceHandle);

        isCapturing = true;

        // Start processing in a separate thread
        captureThread = std::thread([this, procTraceHandle, traceHandle]() mutable {
            printf("Event capture started successfully!\n");
            ProcessTrace(&procTraceHandle, 1, nullptr, nullptr);
            CloseTrace(traceHandle);
            });


        return true;
    }

    // Stop event capture
    void StopEventCapture() {
        if (!isCapturing) {
            printf("Event capture is not running\n");
            return;
        }

        printf("Stopping event capture...\n");
        isCapturing = false;

        // Stop the trace session
        if (sessionHandle != 0) {
            StopTrace(sessionHandle, L"MyETWCaptureSession", nullptr);
            sessionHandle = 0;
        }

        // Wait for capture thread to finish
        if (captureThread.joinable()) {
            captureThread.join();
        }

        // Process any remaining events in buffer
        {
            std::lock_guard<std::mutex> lock(eventBufferMutex);
            if (!eventBuffer.empty()) {
                ProcessEventBatch();
                eventBuffer.clear();
            }
        }

        printf("Event capture stopped\n");
    }

    // Broadcast a custom event message to all registered providers
    void BroadcastEvent(const std::wstring& message) {
        if (registeredHandles.empty()) {
            printf("No providers registered for broadcasting\n");
            return;
        }

        EVENT_DATA_DESCRIPTOR eventData[1];
        EventDataDescCreate(&eventData[0], message.c_str(),
            (message.length() + 1) * sizeof(wchar_t));

        int successCount = 0;
        for (REGHANDLE handle : registeredHandles) {
            ULONG result = EventWrite(handle, nullptr, 1, eventData);
            if (result == ERROR_SUCCESS) {
                successCount++;
            }
        }

        printf("Broadcasted '%ls' to %d/%zu providers\n",
            message.c_str(), successCount, registeredHandles.size());
    }

    // Destructor to unregister all handles on cleanup
    ~ETWProviderManager() {
        StopEventCapture();
        for (REGHANDLE handle : registeredHandles) {
            EventUnregister(handle);
        }
    }
};
