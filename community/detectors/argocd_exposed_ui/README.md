# Exposed Argo CD instances Detector

This Tsunami plugin tests to see if the Argo CD Instances are
misconfigured and exposed.
It Also Checks for CVE-2022-29165 which is an authentication bypass and try to create a separate report for this
Vulnerability.

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
