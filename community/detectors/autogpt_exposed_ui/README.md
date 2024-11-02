# Exposed AutoGPT instances Detector

This Tsunami plugin tests to see if the AutoGpt Instances are publicly exposed and vulnerable to local command
execution.

Please make sure to use AutoGPT instance into an isolated environment when you want to use it in a production server.

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
