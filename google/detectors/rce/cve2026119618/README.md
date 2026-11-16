# CVE-2026-119618 (Apache HTTP Server `mod_http2` RCE) Detector

## Description

This plugin detects Apache HTTP Server instances vulnerable to
**CVE-2026-119618**, an unauthenticated race condition and heap memory
corruption vulnerability in `mod_http2` (`modules/http2/h2_request.c`).

In Apache HTTP Server `2.4.55` through `2.4.70` (and standalone `mod_h2` `2.0.8`
through `2.0.42`), `assign_headers()` clones the incoming stream header table
into the worker-private `r->headers_in` table *before* synthesizing
`Content-Length: 0` onto the shared `c1` connection-pool table (`req->headers`)
for body-less HTTP/2 requests carrying `Content-Type` without `Content-Length`.
Under concurrent worker load, mutating `req->headers` on `c1` causes
unsynchronized `apr_table_t` reallocations and heap corruption. Exploitability
has been proven: Apache's crash-tolerant multi-worker architecture allows
unlimited attempts to probe and align heap state and pivot RIP to ROP gadgets in
`libc` or `httpd` to achieve unauthenticated Remote Code Execution (RCE).

Patched Apache HTTP Server (`2.4.71+` and Linux distribution security backports
of commit `824beab9b9424d6cfb29595248fdbf6c3dddeab1`) writes the synthesized
`Content-Length: 0` directly into `r->headers_in`.

## Target

HTTP/2-enabled Apache HTTP Server deployments over TLS ALPN `h2` or cleartext
prior-knowledge `h2c`.

## Verification

Detection uses a completely non-destructive 3-stream sequential HTTP/2
causal-ablation protocol (strictly `< 10` headers per stream, single stream in
flight, zero concurrency, zero `c1` pool reallocations):

1.  **Stream 1 (Differential `assign_headers()` Probe)**: Sends a body-less
    (`END_STREAM`) HTTP/2 `TRACE` request with `content-type: text/plain` and a
    random lowercase canary header (`x-tsunami-probe: <nonce1>`), omitting
    `content-length`. Verifies HTTP `200`, `Content-Type: message/http`, echoed
    `TRACE <path> HTTP/2.0`, synthesized `Host: <authority>`, Title-Case
    `X-Tsunami-Probe: <nonce1>` (`h2_util_camel_case_header()`), echoed
    `Content-Type: text/plain`, and the **absence** of `Content-Length` in
    `r->headers_in` (patched `>= 2.4.71`, backports, and `<= 2.4.54` echo
    `Content-Length: 0`).
2.  **Stream 3 (Explicit `Content-Length: 0` Control)**: Repeats the request
    with explicit `content-length: 0` and `<nonce2>` and verifies
    `Content-Length: 0` is echoed, ruling out `mod_headers`
    `RequestHeader unset Content-Length` configurations on patched servers.
3.  **Stream 5 (`ap_send_http_trace` 1-Byte Body Control)**: Sends `TRACE` with
    `content-length: 1`, `<nonce3>`, and a 1-byte `DATA` frame (`"x"`),
    verifying Apache's `ap_send_http_trace` body handling (`413` under
    `TraceEnable on` or `200` `message/http` with `Content-Length: 1` and echoed
    `'x'` body under `TraceEnable extended`).
