# CVE-2026-111497 (Google Brotli Decoder Out-of-Bounds Write RCE) Detector

## Description

This plugin detects HTTP services vulnerable to **CVE-2026-111497**, an
out-of-bounds write and memory corruption vulnerability in the Google Brotli
decompression library (`1.0.3` through `1.2.0`).

In unpatched Brotli versions, when a compressed metablock declares a single
distance block type (`NBLTYPESD == 1`), `s->block_length[2]` is initialized to
`1 << 24` (`16,777,216`). If the metablock executes more than `16,777,216`
commands with explicit distances, `s->block_length[2]` decrements to `0` and
invokes `DecodeDistanceBlockSwitch` / `DecodeBlockTypeAndLength`. Unpatched
Brotli returns `BROTLI_FALSE` (`0`) when `max_block_type <= 1`:

- On the fast path (`safe == 0`), `BROTLI_SAFE(DecodeDistanceBlockSwitch(s))`
  ignores the return value, underflows `s->block_length[2]` to `0xFFFFFFFF`,
  and continues decompressing subsequent metablocks to
  `BROTLI_DECODER_RESULT_SUCCESS`.
- On the slow path (`safe == 1`), `BROTLI_SAFE` misinterprets `BROTLI_FALSE` as
  `BROTLI_DECODER_NEEDS_MORE_INPUT`, causing `BrotliDecoderDecompressStream` to
  copy unread input bytes past the 8-byte `s->buffer` union into adjacent
  `BrotliDecoderState` fields (`s->buffer_length`, `s->pos`, `s->ringbuffer`),
  enabling Remote Code Execution (RCE).

Patched Brotli (`1.0.10`, `1.1.1`, `1.2.1`) immediately aborts decompression at
the `16,777,217`th explicit distance symbol with
`BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH` (`-17`).

## Target

Web services and reverse proxies that decompress `Content-Encoding: br` HTTP
request bodies using Brotli `1.0.3` through `1.2.0`, including Node.js (`<=
22.22.0`, `<= 24.13.0`, `<= 25.6.0` with Express `body-parser`, Fastify, or
`zlib`), Python (`brotli` / `brotlicffi`), Bun, and Envoy/Istio with the Brotli
decompressor filter enabled on requests.

## Verification

The detector uses a zero-side-effect, false-positive-free 4-step differential
protocol:

1. Sends a 47-byte valid RFC 7932 Brotli control payload (`Content-Encoding:
   br`) whose decompressed JSON canary (`tsunami_brotli_check_7f9a2b`) is split
   across two metablocks so the contiguous canary string never appears in raw
   wire bytes.
2. Sends a 47-byte invalid Brotli control payload (`Content-Encoding: br`) to
   confirm that the endpoint actively decompresses `Content-Encoding: br` and
   discriminates valid vs. invalid Brotli before ever sending the probe.
3. Sends a compact, zero-side-effect CVE-2026-111497 Brotli bitstream
   (`16,777,216` zero-output `OmitLast7` static dictionary commands with
   `s->pos == 0`, followed by the `16,777,217`th command and a 32-byte
   zero-filled metadata metablock that keeps `s->pos == 0` invariant across all
   arbitrary TCP chunk splits) that decompresses to the exact same JSON as Step
   1 on unpatched Brotli (`1.0.3 .. 1.2.0`) and fails with
   `BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH` on patched Brotli (`1.0.10`,
   `1.1.1`, `1.2.1`).
4. Re-verifies the small Step 1 and Step 2 controls to confirm deterministic
   behavior and target health.
