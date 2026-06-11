# Intel(R) Neural Compressor CVE-2024-22476 Detector

This detector checks for Intel(R) Neural Compressor CVE-2024-22476
Unauthenticated Remote Code Execution (CVE-2024-22476). Improper input
validation in some Intel(R) Neural Compressor software before version 2.5.0 may
allow an unauthenticated user to potentially enable escalation of privilege via
remote access.

-   https://huntr.com/bounties/877a517f-76ec-45be-8d3b-2b5ac471bfeb
-   https://vulners.com/cvelist/CVELIST:CVE-2024-22476

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
