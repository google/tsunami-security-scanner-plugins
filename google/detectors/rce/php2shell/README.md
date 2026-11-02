# PHP2Shell (CVE-2026-109618 / CVE-2026-109619) RCE Detector

## Description
This plugin detects instances of PHP vulnerable to **PHP2Shell**
(CVE-2026-109618 and CVE-2026-109619). The vulnerabilities allow unauthenticated
remote attackers to achieve Remote Code Execution (RCE) by combining
out-of-memory `zend_bailout()` `HashTable` corruption during input variable
registration (`CVE-2026-109618`) with uncleaned cross-request global state in
`session.upload_progress` (`CVE-2026-109619`).

## Target
Web services running unpatched PHP versions `5.4.0` through `8.5.11` (prior to
`8.2.35`, `8.3.36`, `8.4.27`, `8.5.12`, or OS vendor security backports) where
`session.upload_progress.enabled = 1` (default), `session.use_strict_mode = 0`
(default), and startup warnings are rendered in HTTP responses
(`display_errors = On` and `display_startup_errors = On`, which are PHP 8.0+'s
compiled-in defaults when `php.ini-production` is not loaded).

## Verification
Verification uses a zero-side-effect behavioral differential in
`ext/session/session.c` during `PHP Request Startup`:

1. **Startup Flush Probe**: Sends a small multipart `POST` containing an illegal
   session identifier (`tsunami/invalid_sid_<ts>`) in both the `Cookie` header
   and a multipart form field alongside `PHP_SESSION_UPLOAD_PROGRESS` and a
   1-byte file upload. Because `/` and `_` fail session ID character validation,
   `php_session_initialize()` aborts before creating or modifying any session
   file on disk. Unpatched PHP ignores the `FAILURE` return value in
   `php_session_rfc1867_update()` / `php_session_rfc1867_cleanup()` and invokes
   `php_session_flush(1)`, emitting both the invalid-SID warning and
   `Failed to write session data ... in Unknown on line 0`. Patched PHP releases
   and OS vendor backports either return early without calling
   `php_session_flush(1)` or disable `session.upload_progress`.
2. **Causal-Ablation Control**: If the startup flush warning is observed, the
   detector sends a single control request omitting only
   `PHP_SESSION_UPLOAD_PROGRESS` and confirms that the startup flush warning
   disappears, eliminating false positives from static pages or reflection
   endpoints.

> **Scope Limitation**: When `display_startup_errors = Off` or
> `display_errors = Off`, patched and unpatched PHP 8.2–8.5 produce identical
> HTTP responses for all non-OOM inputs, while triggering `memory_limit`
> introduces worker crash / memory-corruption side effects. Such instances
> cannot be actively verified without side effects or version-banner false
> positives on OS vendor backports.

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
