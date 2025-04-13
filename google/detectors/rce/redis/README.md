# Unauthenticated Redis allowing RCE VulnDetector

A `VulnDetector` plugin for Tsunami detecting this vulnerability.

Redis does not have authentication set by default, when exposed to the internet,
this allows arbitrary code executions on the Redis instance.

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
