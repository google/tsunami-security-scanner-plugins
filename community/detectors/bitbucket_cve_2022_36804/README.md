# BitBucket CVE-2022-36804 command injection vulnerability Detector

## CVE

[CVE-2022-36804](https://github.com/advisories/GHSA-vcm2-j8f4-m7fj)

## Description of Vulnerability

This detector checks for BitBucket CVE-2022-36804 command injection
vulnerability.

A vulnerability in Bitbucket allows remote code execution. An attacker with
read to a repository can execute arbitrary code by sending a malicious HTTP
request. Versions between 6.10.17 and 8.3.0 (included) are affected.

## Requirements

- At least one repository must be readable;
- It must already contain some files (must not be uninitialized);
- It must have a default branch configured.

## Related Articles

https://jira.atlassian.com/browse/BSERV-13438

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
