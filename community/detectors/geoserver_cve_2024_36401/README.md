# Geoserver CVE-2024-36401 RCE Detector

This detector checks for Geoserver RCE (CVE-2024-36401). Multiple OGC request
parameters allow Remote Code Execution (RCE) by unauthenticated users through
specially crafted input against a default GeoServer installation due to unsafely
evaluating property names as XPath expressions.

Ref:

-   https://github.com/advisories/GHSA-6jj6-gm7p-fcvv

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
