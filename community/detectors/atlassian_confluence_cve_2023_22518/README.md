# Atlassian Confluence Data Center CVE-2023-22518 Detector

This detector checks for Atlassian Confluence Data Center Improper Authorization
(CVE-2023-22518). All versions of Confluence Data Center and Server are affected
by this vulnerability. This Improper Authorization vulnerability allows an
unauthenticated attacker to reset Confluence and create a Confluence instance
administrator account. Using this account, an attacker can then perform all
administrative actions that are available to Confluence instance administrator
leading to a full loss of confidentiality, integrity and availability.

Ref:

-   https://confluence.atlassian.com/security/cve-2023-22518-improper-authorization-vulnerability-in-confluence-data-center-and-server-1311473907.html

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
