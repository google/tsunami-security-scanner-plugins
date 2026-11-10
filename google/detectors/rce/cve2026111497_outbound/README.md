# Outbound CVE-2026-111497 (Google Brotli Decoder RCE) Detector

## Description

This plugin (`Cve2026111497OutboundDetector`) detects web applications and CMSs
vulnerable to unauthenticated Remote Code Execution via **CVE-2026-111497** (an
out-of-bounds write in the Google Brotli decompression library `libbrotlidec`
`1.0.3` through `1.2.0`) triggered when an unauthenticated endpoint fetches an
attacker-supplied URL and automatically decompresses `Content-Encoding: br` HTTP
responses:

1.  **Multi-CMS XML-RPC `pingback.ping`** (WordPress `/xmlrpc.php`, Drupal
    `/xmlrpc.php` and `/services/xmlrpc`, b2evolution `/xmlsrv/xmlrpc.php`,
    Serendipity `/comment.php?type=pingback`, Movable Type `/mt-xmlrpc.cgi`,
    TikiWiki `/tiki-xmlrpc.php`, DokuWiki Linkback
    `/lib/plugins/linkback/exe/pingback.php/{id}` and custom endpoints
    advertised via same-origin `X-Pingback` response headers, plus common CMS
    installation subpaths): Supports both retrying HTTP transports (such as
    WordPress `WpOrg\Requests\Transport\Curl`, which retries with
    `Accept-Encoding: none` when `libbrotlidec` rejects a stream) and
    non-retrying `libcurl`/Guzzle HTTP clients (via unmasked XML-RPC fault-code
    differentials).
2.  **Next.js Image Optimizer (`/_next/image`)**: When a Next.js server permits
    remote image optimization (`images.remotePatterns` / `images.domains`),
    `GET /_next/image?url=<tcs_url>&w=64&q=75` invokes Node.js `fetch()`
    (`undici`), which advertises `Accept-Encoding: gzip, deflate, br` and
    streams `Content-Encoding: br` responses through Node.js's bundled
    `libbrotlidec` before checking the response `Content-Type` header.

## Verification

Detection uses a zero-side-effect, false-positive-free 4-step differential
protocol backed by the **Tsunami Callback Server (TCS)** HTTP recording presets
(`?response=brotli_valid`, `brotli_invalid`, `brotli_cve_2026_111497` with
`&no_br_cbid=` retry attribution):

1.  **Discovery**: If TCS is not enabled
    (`!tcsClient.isCallbackServerEnabled()`), the detector logs a warning and
    skips cleanly without sending traffic. For XML-RPC, it extracts same-origin
    `X-Pingback` URLs from crawled response headers and probes CMS XML-RPC
    routes, querying `system.listMethods` (immediately skipping endpoints whose
    method list omits `pingback.ping`, or falling back to RSD / `IXR_Server`
    POST-only banner / dedicated pingback XML-RPC responses when
    `system.listMethods` is blocked) and discovering candidate target posts via
    `/wp-json/wp/v2/posts`, RSS feeds (`/?feed=rss2`, `/rss.xml`), 200 `GET`
    crawled pages, and canonical fallbacks (`/?p=1`, `/node/1`).
2.  **Step 1 (Valid Brotli Control)**: Points `pingback.ping` or `/_next/image`
    to a TCS callback URL with `?response=brotli_valid&no_br_cbid=<cbid2>`,
    which serves a 57-byte valid RFC 7932 Brotli document. Confirms an outbound
    `br` interaction on the primary CBID and no fallback retry on `no_br_cbid`.
3.  **Step 2 (Invalid Brotli Control)**: Uses `?response=brotli_invalid`,
    serving a 57-byte invalid Brotli stream (`0x7b...`, failing
    `BROTLI_DECODER_ERROR_FORMAT_PADDING_2`). Verifies either an
    `Accept-Encoding: none` retry on `no_br_cbid` (WordPress `WpOrg\Requests`),
    a strict unmasked XML-RPC fault differential (`32`/`17` vs. `16`) for
    non-retrying `libcurl`/Guzzle clients, or a `400` vs. `500`/`502` HTTP
    status differential on `/_next/image`.
4.  **Step 3 (Zero-Side-Effect CVE-2026-111497 Probe)**: Uses
    `?response=brotli_cve_2026_111497`, streaming the `NBLTYPESD == 1`
    `16,777,217`-command zero-output `OmitLast7` bitstream with `s->pos == 0`
    invariant (53 decompressed bytes, zero memory corruption, zero database
    writes). Unpatched `libbrotlidec` (`1.0.3 .. 1.2.0`) completes decompression
    identically to Step 1, whereas patched `libbrotlidec` (`1.0.10`, `1.1.1`,
    `1.2.1`, Debian `1.1.0-2+deb13u1`) aborts at command `16,777,217`.
5.  **Step 4 (Post-Probe Health & Determinism Verification)**: Re-runs both
    57-byte valid and invalid controls via TCS to verify service health and
    deterministic behavior before reporting `VULNERABILITY_VERIFIED`.

## Callback Server Requirements

This detector requires Tsunami's Callback Server (`plugin.callbackserver` in
`tsunami.yaml` or `--callback-server-*` CLI flags) running a TCS build that
supports the `brotli_*` HTTP recording presets.
