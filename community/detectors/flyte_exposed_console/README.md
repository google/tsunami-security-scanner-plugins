# Exposed Flyte Console Detector

This Tsunami plugin identifies publicly exposed Flyte Consoles. Once detected, it creates a project and task within the console, executes the task to run remote code, and then receives a callback at the Tsunami callback server.

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
