# NGINX CVE-2026-123007 VulnDetector

This plugin detects NGINX Open Source (`1.9.5` through `1.30.6` and `1.31.0`
through `1.31.8`) and unpatched NGINX Plus or OS distribution builds vulnerable
to the HTTP/2 queued-frame flow-control window validation bypass and heap buffer
overflow (`CVE-2026-123007`).

## Detection Mechanism

1.  **Phase 1 — NGINX HTTP/2 Framing & Deterministic Static Path Discovery**:
    Connects over TLS ALPN `h2` or cleartext `h2c` prior knowledge, verifies
    NGINX `ngx_http_v2_init()`'s `18`-byte or `24`-byte initial `SETTINGS` frame
    plus Stream `0` `WINDOW_UPDATE` increment `2147418112`, excludes non-NGINX
    intermediaries (`Via`, `AWSALB*`, non-NGINX `Server`), and selects a
    deterministic `<= 64 KiB` static response path.
2.  **Phase 2 — Non-Destructive Stream 0 `WINDOW_UPDATE` Differential**: Clamps
    the socket receive buffer so accepted `DATA` frames remain queued in
    `h2c->last_out`, verifies either concurrency saturation (a contiguous tail
    of `RST_STREAM(REFUSED_STREAM)` frames) or high-`MAX_CONCURRENT_STREAMS`
    queued-window / parked-stream (`h2c->waiting`) retention where flushed
    pre-`PING` `DATA` bytes stay strictly below the Stream `0` `WINDOW_UPDATE`
    differential, and confirms connection liveness across pre/post/liveness
    `PING` ACKs without sending client `RST_STREAM` frames.

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
