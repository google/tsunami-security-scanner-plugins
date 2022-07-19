# Confluence CVE-2022-26134 RCE Detector

This detector checks for [CVE-2022-26134](https://confluence.atlassian.com/doc/confluence-security-advisory-2022-06-02-1130377146.html),
vulnerabilities in Atlassian Confluence.

This detector works with and without a callback server.

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
