# Alibaba-Nacos <= 1.4.0 CVE-2021-29442 execute arbitrary SQL without authentication vulnerability Detector

This detector checks for Alibaba-Nacos <= 1.4.0 CVE-2021-29442 execute arbitrary SQL without authentication vulnerability.
When the nacos version is less than or equal to 1.4.0, 
it can be accessed without authentication and execute arbitrary SQL queries, 
which leads to the disclosure of sensitive information.
https://github.com/alibaba/nacos/issues/4463

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
