# Outbound CVE-2026-111497 (Google Brotli Decoder RCE) Detector

## Description

This plugin detects WordPress installations vulnerable to unauthenticated
Remote Code Execution via **CVE-2026-111497** (an out-of-bounds write in the
Google Brotli decompression library `libbrotlidec` `1.0.3` through `1.2.0`)
triggered through WordPress's unauthenticated `xmlrpc.php` `pingback.ping`
endpoint.

Even when Apache `mod_brotli` is not enabled on incoming HTTP requests (as in
Docker's official `wordpress` container images), WordPress's `pingback.ping`
handler invokes `wp_safe_remote_get()` via `WpOrg\Requests\Transport\Curl` with
`CURLOPT_ENCODING = ""`. When the underlying `libcurl` is linked against
`libbrotlidec` (such as Debian 13 `libbrotli1` `1.1.0-2+b7` shipped in
pre-patch official `wordpress` Docker images), `libcurl` advertises
`Accept-Encoding: deflate, gzip, br, zstd` on the outbound pingback verification
`GET` request and streams any `Content-Encoding: br` HTTP response directly into
`BrotliDecoderDecompressStream` before PHP's 150 KB decompressed
`limit_response_size` check runs. Notably, filtering `xmlrpc_enabled` to
`false` in WordPress only disables authenticated XML-RPC methods and leaves
unauthenticated `pingback.ping` active unless `pingback.ping` is explicitly
removed from `xmlrpc_methods` or `/xmlrpc.php` is blocked.

## Verification

Detection uses a zero-side-effect, false-positive-free 4-step differential
protocol backed by the **Tsunami Callback Server (TCS)** HTTP recording presets
(`?response=brotli_valid`, `brotli_invalid`, `brotli_cve_2026_111497` with
`&no_br_cbid=` retry attribution):

1. **Discovery**: If TCS is not enabled
   (`!tcsClient.isCallbackServerEnabled()`), the detector logs a warning and
   skips cleanly without sending traffic. Otherwise, it verifies WordPress
   XML-RPC (`GET /xmlrpc.php?rsd` and `POST /xmlrpc.php` `system.listMethods`
   containing `pingback.ping`) and locates a published post with pingbacks open
   via `/wp-json/wp/v2/posts`, `/?feed=rss2`, or `/?p=1`.
2. **Step 1 (Valid Brotli Control)**: Invokes `pingback.ping` pointing to a TCS
   callback URL with `?response=brotli_valid&no_br_cbid=<cbid2>`, which serves a
   57-byte valid RFC 7932 Brotli document without a `<title>` element (so
   WordPress aborts before registering any pingback comment). Confirms an
   outbound `br` interaction on the primary CBID and no fallback retry on
   `no_br_cbid`.
3. **Step 2 (Invalid Brotli Control)**: Uses `?response=brotli_invalid`, serving
   a 57-byte invalid Brotli stream (`0x7b...`, failing
   `BROTLI_DECODER_ERROR_FORMAT_PADDING_2`). Confirms that `libcurl` fails
   Brotli decompression (`CURLE_BAD_CONTENT_ENCODING`) and
   `WpOrg\Requests\Transport\Curl` immediately issues a second `GET` retry with
   `CURLOPT_ENCODING = "none"` (`Accept-Encoding: none`), recorded by TCS under
   `no_br_cbid`.
4. **Step 3 (Zero-Side-Effect CVE-2026-111497 Probe)**: Uses
   `?response=brotli_cve_2026_111497`, streaming the `NBLTYPESD == 1`
   `16,777,217`-command zero-output `OmitLast7` bitstream with `s->pos == 0`
   invariant (53 decompressed bytes, zero memory corruption, zero database
   writes). Unpatched `libbrotlidec` (`1.0.3 .. 1.2.0`) completes decompression
   with `0` `Accept-Encoding: none` retries, whereas patched `libbrotlidec`
   (`1.0.10`, `1.1.1`, `1.2.1`, Debian `1.1.0-2+deb13u1`) aborts at command
   `16,777,217` with `BROTLI_DECODER_ERROR_FORMAT_BLOCK_LENGTH_2` and triggers
   the `Accept-Encoding: none` retry recorded on `no_br_cbid`.
5. **Step 4 (Post-Probe Health & Determinism Verification)**: Re-runs both
   57-byte valid and invalid controls via TCS to verify service health and
   deterministic behavior before reporting `VULNERABILITY_VERIFIED`.

## Callback Server Requirements

This detector requires Tsunami's Callback Server (`plugin.callbackserver` in
`tsunami.yaml` or `--callback-server-*` CLI flags) running a TCS build that
supports the `brotli_*` HTTP recording presets. Note that WordPress's
`wp_http_validate_url()` permits outbound pingback requests only to ports `80`,
`443`, and `8080` by default (standard production TCS HTTP recording deployments
use port `80`).
