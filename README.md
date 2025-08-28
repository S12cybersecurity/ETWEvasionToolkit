# ETW Evasion Toolkit
Toolkit of Projects to attack and evade Event Trace for Windows

## ETW Ghost Logger

ETW Ghost Logger is a project within the ETW Evasion Toolkit designed to stealthily intercept and log Event Tracing for Windows (ETW) events in a target process. By hooking into the EtwEventWrite function, it captures and analyzes system events without detection, providing detailed insights into event data in both hexadecimal and ASCII formats.

## ETW Interceptor

ETW Interceptor provides an effective mechanism for controlling which events are logged in the Event Tracing for Windows (ETW) system, allowing specific event types to be suppressed based on their IDs. This can be particularly useful for evading detection during the execution of certain actions, such as process creation, logons, or privileged operations.

## ETW Noise

This technique focuses on injecting fake ETW (Event Tracing for Windows) events by hooking the EtwEventWrite function using a guard page and vectored exception handling. Instead of blocking or removing telemetry, it injects realistic but harmless events—like file reads, network calls, or DLL loads—to make malicious behavior blend in with normal system activity. This helps confuse security tools like EDRs by adding believable, noisy, or redirected telemetry, making it harder to spot real threats in the middle of fake logs.

## ETW Event Register Abuser

This tool is a C++ utility for abusing ETW (Event Tracing for Windows) providers. It works by enumerating all ETW providers on a system, registering itself under their GUIDs, and then broadcasting custom messages that appear as legitimate events. While running, it can also capture and display events in real time, converting raw event data into a human-readable format. The main program lets a user supply any message and specify how many times it should be sent, after which the tool injects the message into multiple providers simultaneously. In short, it demonstrates how ETW can be misused both for event injection and for capturing system telemetry, making it a powerful proof-of-concept for testing monitoring systems or researching detection evasion techniques.

