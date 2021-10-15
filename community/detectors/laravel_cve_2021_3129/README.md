# Laravel CVE-2021-3129 Detector

This plugin detects an pre-auth remote code execution vulnerability in Laravel <= 8.4.2 running in debug mode.

More information on the vulnerability:

* [CVE-2021-3129](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3129)
* [National Vulnerability Database (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2021-3129)

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

A Tsunami identifiable jar file is located in the `build/libs` directory.
