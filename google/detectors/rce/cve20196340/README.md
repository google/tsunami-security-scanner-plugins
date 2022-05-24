# Drupal CVE-2019-6340 Detector

This plugin for Tsunami detects a Drupal remote code execution (RCE)
caused by unsafe deserialization in Rest API module.

More information on the vulnerability:

* [CVE-2019-6340](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-6340)
* https://www.securityfocus.com/bid/107106

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
