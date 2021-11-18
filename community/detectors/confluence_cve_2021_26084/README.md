# Atlassian Confluence Pre-Auth OGNL Injection

This detector checks for CVE-2021-26084 Confluence Server Webwork Pre-Auth OGNL
Injection.An OGNL injection vulnerability exists that allows an unauthenticated
attacker to execute arbitrary code on a Confluence Server or Data Center
instance.

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
