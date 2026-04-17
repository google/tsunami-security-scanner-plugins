# CVE-2023-26360 Detector

Description: Adobe ColdFusion versions 2018 Update 15 (and earlier) and 2021
Update 5 (and earlier) are affected by an Improper Access Control vulnerability
that could result in unauthenticated file read and arbitrary code execution in
the context of the current user. Exploitation of this issue does not require
user interaction.

-   https://nvd.nist.gov/vuln/detail/CVE-2023-26360
-   https://helpx.adobe.com/security/products/coldfusion/apsb23-25.html

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
