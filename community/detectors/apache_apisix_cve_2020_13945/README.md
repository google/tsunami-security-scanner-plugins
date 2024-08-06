# Apache APISIX RCE CVE-2020-13945 Detector

Apache APISIX 1.2, 1.3, 1.4, and 1.5 is susceptible to insufficiently protected credentials. An attacker can enable the
Admin API and delete the Admin API access IP restriction rules. Eventually, the default token is allowed to access
APISIX management data.
See https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-202-13945 for a details.

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```
