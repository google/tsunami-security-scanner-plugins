# Alibaba Nacos CVE-2021-29441 User-Agent authentication bypass vulnerability Detector

This detector checks for Alibaba Nacos CVE-2021-29441 User-Agent authentication bypass vulnerability.
When the nacos version is less than or equal to 1.4.0, when accessing the http endpoint, 
adding the User-Agent: Nacos-Server header can bypass the authentication restriction and access any http endpoint.
https://github.com/alibaba/nacos/issues/4593
https://github.com/alibaba/nacos/pull/4703
https://github.com/advisories/GHSA-36hp-jr8h-556f
https://nvd.nist.gov/vuln/detail/CVE-2021-29441

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
