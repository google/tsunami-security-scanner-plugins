# Apache Druid CVE-2021-25646 Pre-Auth RCE vulnerability Detector

This detector checks for Apache Druid <= 0.20.0 CVE-2021-25646 Pre-Auth RCE vulnerability.
Apache Druid includes the ability to execute user-provided JavaScript code embedded in various types of requests.
This functionality is intended for use in high-trust environments, and is disabled by default.
However, in Druid 0.20.0 and earlier, it is possible for an authenticated user to send a
specially-crafted request that forces Druid to run user-provided JavaScript code for that request,
regardless of server configuration.
This can be leveraged to execute code on the target machine with the privileges of the Druid server process.
https://nvd.nist.gov/vuln/detail/CVE-2021-25646

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
