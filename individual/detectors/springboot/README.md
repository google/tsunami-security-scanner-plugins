# Spring-Boot Actuator Detector

This detector checks activated Spring-Boot Actuator by sending a probe ping to
/actuator/* endpoint as an anonymous user. The Spring-Boot Actuator 
will show the Server Information and other result, which allows the anonymous user to display 
api response that could to lead sensitive information leak and DoS.

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
