# MLflow LFI/RFI CVE-2023-6977 Detector

This detector checks for MLflow LFI/RFI vulnerability (CVE-2023-6977). This
vulnerability enables malicious users to read sensitive files on the server. It
encompasses both CVE-2023-1177 and CVE-2023-2780 because exploit of
CVE-2023-6977 bypasses patches of these vulnerabilities by using symlinks.

-   https://huntr.com/bounties/fe53bf71-3687-4711-90df-c26172880aaf
-   https://nvd.nist.gov/vuln/detail/CVE-2023-6977

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
