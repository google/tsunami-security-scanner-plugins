# CVE-2023-0669 GoAnywhere MFT RCE vulnerability Detector

## CVE

[CVE-2023-0669](https://nvd.nist.gov/vuln/detail/CVE-2023-0669)

## Description of Vulnerability

This detector checks for GoAnywhere MFT RCE vulnerability CVE-2023-0669.

GoAnywhere MFT suffers from a pre-authentication command injection vulnerability in the License Response Servlet due to
deserializing an arbitrary attacker-controlled object.

All versions prior to 7.1.1 are affected,Update GoAnywhere MFT to a version that provides a fix 7.1.2 or later

## Related Articles

https://nvd.nist.gov/vuln/detail/CVE-2023-0669

https://www.vicarius.io/vsociety/posts/unauthenticated-rce-in-goanywhere

https://www.cve.org/CVERecord?id=CVE-2023-0669

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
