# Information leak via Kubernetes read-only-port feature

This is a `VulnDetector` plugin for Tsunami to find Kubernetes clusters
with the read-only-port feature being present and leaking information about the
cluster.

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
