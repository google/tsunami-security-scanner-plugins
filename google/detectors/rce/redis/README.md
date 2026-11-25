# Redis / Valkey Unauthenticated Access & RCE Detector

This detector checks TCP and TLS endpoints for unauthenticated Redis, Valkey,
and RESP2-compatible database exposure and separates unauthenticated database
read/write access from configurations that allow direct OS remote code execution
(RCE) on the Redis host.

## Findings Emitted

For each vulnerable endpoint, the detector emits **at most one** mutually
exclusive finding:

1.  **`REDIS_UNAUTHENTICATED_COMMAND_EXECUTION` (`CRITICAL`)**: Emitted when the
    instance accepts unauthenticated RESP2 commands **and** live runtime
    configuration permits direct OS file writes (`CONFIG SET dir` /
    `dbfilename`) or native shared-library loading (`MODULE LOAD` / `MODULE
    LOADEX`) — covering unprotected Redis `< 7.0` defaults as well as Redis `>=
    7.0` and Valkey instances misconfigured with `enable-protected-configs yes`
    / reachable `local` or `enable-module-command yes` / reachable `local`.
2.  **`REDIS_UNAUTHENTICATED_READ_WRITE_ACCESS` (`HIGH`)**: Emitted when
    `INFO server` confirms unauthenticated Redis/Valkey protocol access without
    confirming unlocked direct OS RCE configuration gates (`CONFIG SET
    dir`/`dbfilename` or `MODULE LOAD`/`LOADEX`). Kept at `HIGH` severity
    because unauthenticated data read/write allows full key
    exfiltration/tampering and downstream application RCE when connected workers
    deserialize values with Python `pickle`, Ruby `Marshal`, Java serialization,
    or PHP session handlers.

## Safe Non-Destructive Probing

All probes use a minimal inline RESP2 wire helper (`64 KiB` session budget, `5s`
deadline, zero external client dependencies) without modifying keys,
configuration, working directory, or loaded modules:

-   `INFO server`: Verifies unauthenticated Redis/Valkey access (`-NOAUTH` /
    `-NOPERM` immediately exits cleanly with zero findings).
-   `CONFIG GET enable-protected-configs` followed (only when not `"no"`) by
    `CONFIG SET dbfilename "a/b"` on native Redis `>= 3.2` and Valkey (rejected
    by `pathIsBaseName` with `"dbfilename can't be a path, just a filename"`
    after ACL and `PROTECTED_CONFIG` checks, before mutating `rdb_filename`), or
    synthetic `CONFIG SET __tsunami_ro_probe__ ""` on legacy Redis `< 3.2`.
-   `CONFIG GET enable-module-command` followed (only when not `"no"`) by
    `MODULE LOADEX "" CONFIG` (rejected by `parseLoadexArguments` before
    `dlopen`) or `MODULE UNLOAD __tsunami_ro_probe__` on Redis 4.0–6.2.

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
