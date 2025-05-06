# ETW Evasion Toolkit
Toolkit of Projects to attack and evade Event Trace for Windows

## ETW Ghost Logger

ETW Ghost Logger is a project within the ETW Evasion Toolkit designed to stealthily intercept and log Event Tracing for Windows (ETW) events in a target process. By hooking into the EtwEventWrite function, it captures and analyzes system events without detection, providing detailed insights into event data in both hexadecimal and ASCII formats.

## ETW Interceptor

ETW Interceptor provides an effective mechanism for controlling which events are logged in the Event Tracing for Windows (ETW) system, allowing specific event types to be suppressed based on their IDs. This can be particularly useful for evading detection during the execution of certain actions, such as process creation, logons, or privileged operations.
