# Grafana Pre-Auth Arbitrary File Reading vulnerability Detector

This detector checks for Grafana Pre-Auth Arbitrary File Reading vulnerability (CVE_2021_43798).
In Grafana 8.0.0 to 8.3.0, there is an endpoint that can be accessed without authentication.
This endpoint has a directory traversal vulnerability, and any user can read any file on the server
without authentication, causing information leakage.

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
