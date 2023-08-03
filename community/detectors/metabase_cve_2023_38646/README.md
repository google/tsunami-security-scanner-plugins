# Pre-Auth Remote Code Execution in Metabase CVE-2023-38646 Detector

Metabase open source before 0.46.6.1 and Metabase Enterprise before 1.46.6.1 has a vulnerability that allows attackers
to execute arbitrary commands on the server, at the server's privilege level. Authentication is not required for
exploitation.

References:

1. https://www.metabase.com/blog/security-advisory-h2
2. https://www.metabase.com/blog/security-advisory
2. https://blog.calif.io/p/reproducing-cve-2023-38646-metabase
2. https://blog.assetnote.io/2023/07/22/pre-auth-rce-metabase/

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```
