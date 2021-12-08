# GoCD Pre-Auth Arbitrary File Reading vulnerability Detector

This detector checks for GoCD Pre-Auth Arbitrary File Reading vulnerability.
In GoCD 21.2.0 and earlier, there is an endpoint that can be accessed without authentication.
This endpoint has a directory traversal vulnerability, and any user can read any file on the server without authentication, causing information leakage.
https://www.gocd.org/releases/#21-3-0

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
