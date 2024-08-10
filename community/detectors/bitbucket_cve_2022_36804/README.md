# BitBucket CVE-2022-36804 command injection vulnerability Detector

## CVE

[CVE-2022-36804](https://github.com/advisories/GHSA-vcm2-j8f4-m7fj)

## Description of Vulnerability

This detector checks for BitBucket CVE-2022-36804 command injection vulnerability.

A vulnerability in Bitbucket allows a remote code execution.
An attacker with access with read or public access to a
repository can execute arbitrary code by sending a malicious
HTTP request. All versions released after 6.10.17
including 7.0.0 and newer are affected, this means that all
instances that are running any versions between 7.0.0 and
8.3.0 inclusive can be exploited by this vulnerability.

## Related Articles

https://jira.atlassian.com/browse/BSERV-13438

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.