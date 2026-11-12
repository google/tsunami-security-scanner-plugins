# WebLogic IIOP Deserialization (CVE-2024-21181)

## Description

CVE-2024-21181 is a critical vulnerability in Oracle WebLogic Server. The vulnerability lies in the way it
handles T3/IIOP requests. When performing the lookup for a Reference object the unsafe deserialization is triggered.

### Detector's implementation

This detector only exploits the deserialization vulnerability to perform a simple DNS callback. 
Even though this doesn't leak any sensitive data, it hints that a more complex gadget chain is possible.
Implementing a gadget-chain that leverages the deserialization vulnerability to achieve a complete RCE
it's outside the scope of the scanner.

**The detector needs the Tsunami Callback Server with the DNS mode enabled.**

The detector does not need any Oracle library, as (part of) the protocol used for the communication has been reverse-engineered and is handled entirely by the detector itself.

## Affected Versions

-  WebLogic Server 12 <= v12.2.1.4.0
-  WebLogic Server 14 <= v14.1.1.0.0

## Build the plugin

```shell
./gradlew build
```

The Tsunami identifiable jar file is located in the `build/libs` directory.

## Notes
### T3 Protocol

This detector uses the IIOP protocol to trigger the deserialization bug. It should theoretically be possible to use the T3 protocol, but during testing we found that using T3 seem to actually trigger the bug on the client side – i.e. on our own detector – instead that on the server.