# Apache APISIX Default Token RCE  Detector

Apache APISIX has a built-in default API KEY. If the user does not proactively modify it (which few will), Lua scripts
can be executed directly through the API interface, which can lead to RCE vulnerabilities.

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```
