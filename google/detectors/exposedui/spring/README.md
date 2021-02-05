# Exposed Spring Boot Actuator Endpoint Detector

This detector checks whether sensitive Actuator endpoints of a Spring Boot
application are exposed. Some of the default endpoints like `/heapdump` may
expose sensitive information while others like `/env` might lead to RCE. See
[this research](https://www.veracode.com/blog/research/exploiting-spring-boot-actuators)
for more details about the exploit.

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.

## Exported config values

Config properties prefix: `plugins.google.detector.exposed_ui.spring`.

Config values:

*   `endpoint_prefixes`: specifies which prefixes should be prepended to the
    Actuator endpoint. By default the detector uses the empty prefix (for Spring
    1.x) and `/actuator` prefix (for Spring 2.x).

Example YAML config:

```yaml
plugins:
  google:
    detector:
      exposed_ui:
        spring:
          endpoint_prefixes:
            - ""
            - "/actuator"
            - "/management"
```
