# Unauthenticated Redis Command Access VulnDetector

A `VulnDetector` plugin for Tsunami that executes `INFO server` over TCP
without authentication to detect unauthenticated Redis protocol access.

Unauthenticated Redis access exposes keyspace read/write operations, `MONITOR`
traffic capture, internal VPC SSRF, and downstream application RCE when workers
deserialize Redis values unsafely (`pickle`, `Marshal`, Java/PHP
serialization). Direct OS RCE on the Redis host additionally depends on server
version and configuration (`Redis < 7.0`, relaxed `enable-protected-configs` or
`enable-module-command`, or unpatched engine/Lua CVEs).

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
