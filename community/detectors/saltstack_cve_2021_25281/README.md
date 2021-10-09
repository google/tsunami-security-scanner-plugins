# SaltStack Salt-API Unauthenticated Remote Command Execution vulnerability (CVE-2021-25281) Detector

This detector checks for SaltStack Salt-API Unauthenticated Remote Command Execution vulnerability (CVE-2021-25281).
SaltAPI does not honor eauth credentials for the wheel_async client.
Thus, an attacker can remotely run any wheel modules on the master.
The Salt-API does not have eAuth credentials for the wheel_async client.

https://nvd.nist.gov/vuln/detail/CVE-2021-25281

https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-25281

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
