# Apache APISIX RCE CVE-2022-24112 Detector

Some of Apache APISIX 2.x versions allows attacker to
bypass IP restrictions of Admin API through the batch-requests plugin.
See https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-24112 for a details.

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```
