# Alibaba Nacos CVE-2021-29442 execute arbitrary SQL without authentication vulnerability Detector

This detector checks for Alibaba Nacos CVE-2021-29442 execute arbitrary SQL without authentication vulnerability.
When the nacos version is less than or equal to 1.4.0, 
it can be accessed without authentication and execute arbitrary SQL queries, 
which leads to the disclosure of sensitive information.
https://github.com/alibaba/nacos/issues/4463
https://github.com/alibaba/nacos/pull/4517
https://nvd.nist.gov/vuln/detail/CVE-2021-29442
https://github.com/advisories/GHSA-xv5h-v7jh-p2qh

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
