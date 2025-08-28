#include <windows.h>
#include <iostream>
#include <string>
#include <thread>
#include <chrono>
#include <climits>

// Include the header where your ETWProviderManager class is declared.
// If the class is in the same translation unit, you can remove this and paste it above.
#include "ETW.h"

static void PrintUsage(const wchar_t* exe) {
    std::wcout << L"Usage: " << exe << L" \"<event text>\" <times>\n"
        << L"  <event text> : Message to send to each registered provider.\n"
        << L"  <times>      : Positive integer for how many times to send it.\n";
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 3) {
        PrintUsage(argv[0]);
        return 1;
    }

    const std::wstring message = argv[1];

    wchar_t* endPtr = nullptr;
    long timesLong = wcstol(argv[2], &endPtr, 10);
    if (endPtr == argv[2] || timesLong <= 0 || timesLong > INT_MAX) {
        std::wcerr << L"Invalid <times> value. It must be a positive integer.\n";
        PrintUsage(argv[0]);
        return 1;
    }
    const int times = static_cast<int>(timesLong);

    ETWProviderManager manager;

    // 1) Enumerate all ETW providers on the system.
    if (!manager.EnumerateSystemProviders()) {
        std::wcerr << L"Failed to enumerate ETW providers.\n";
        return 1;
    }

    // 2) Register as many providers as possible ("subscribe to all").
    //    The class method takes a max count; pass a very large number to attempt all.
    if (!manager.RegisterAsPopularProviders(INT_MAX)) {
        std::wcerr << L"Failed to register with any ETW providers.\n";
        return 1;
    }   

    // 3) Start capture (subscribe/enable providers & begin processing).
    if (!manager.StartEventCapture()) {
        std::wcerr << L"Failed to start event capture.\n";
        return 1;
    }

    // Small warm-up so the session is fully live before writes.
    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    // 4) Broadcast the message the requested number of times.
    for (int i = 0; i < times; ++i) {
        manager.BroadcastEvent(message);
        // Brief pause to avoid hammering; also gives the consumer thread time to process.
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    //// Optional: let the capture thread process remaining events briefly.
    //std::this_thread::sleep_for(std::chrono::seconds(2));

    // 5) Stop capture cleanly (also happens in destructor, but explicit is nice).
    manager.StopEventCapture();

    std::wcout << L"Done.\n";
    return 0;
}
