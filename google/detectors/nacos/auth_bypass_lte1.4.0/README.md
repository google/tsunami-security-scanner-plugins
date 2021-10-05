# Alibaba-Nacos <= 1.4.0 User-Agent authentication bypass vulnerability Detector

This detector checks for Alibaba-Nacos <= 1.4.0 User-Agent authentication bypass vulnerability.
When the nacos version is less than or equal to 1.4.0, when accessing the http endpoint, 
adding the User-Agent: Nacos-Server header can bypass the authentication restriction and access any http endpoint.
https://github.com/alibaba/nacos/issues/4593

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
