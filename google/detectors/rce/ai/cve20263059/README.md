# SGLang Unauthenticated ZMQ Deserialization RCE (CVE-2026-3059) Detector

This detector identifies SGLang instances vulnerable to **CVE-2026-3059**, a
critical (CVSS 9.8) unauthenticated remote code execution vulnerability in the
SGLang multimodal generation runtime.

## Vulnerability Details

* **CVE**: CVE-2026-3059
* **Severity**: Critical (CVSS 9.8)
* **CWE**: CWE-502 (Deserialization of Untrusted Data)
* **Affected Versions**: 0.5.5 – 0.5.9 (Fixed in 0.5.10)

### Technical Summary

In affected versions of SGLang, the multimodal generation module exposes a
ZeroMQ (ZMQ) broker socket on TCP port `http_port + 1` (for example, port
`30001` when the HTTP server runs on default port `30000`) without
authentication. Incoming messages on this socket are deserialized directly via
`pickle.loads()`, allowing an unauthenticated remote attacker to achieve remote
code execution.

### Detection Logic

1. Fingerprints the target HTTP service using SGLang's `/get_server_info` and
   `/get_model_info` endpoints (and verifies the version if exposed).
2. Connects to the adjacent TCP port (`http_port + 1`) and performs a safe,
   non-destructive ZeroMQ Message Transport Protocol (ZMTP 3.0) greeting
   handshake to verify whether an unauthenticated (`NULL` mechanism) ZMQ broker
   is exposed.

## Build and Test

Run unit tests using Gradle:

```bash
./gradlew test
```

