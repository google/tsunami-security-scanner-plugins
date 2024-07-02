# Exposed Apache Airflow Detector

This plugin for Tsunami detects publicly exposed apache airflow instances.
First it tries to receive a callback to the tsunami callback server and if it failed, it sends an HTTP request to an API
endpoint to match the response with a pattern.

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
