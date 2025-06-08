# Flowise UI Exposed Detector

This Tsunami plugin detects exposed Flowise UI instances. Flowise is a drag & drop UI tool for building LLM applications. When exposed without proper authentication, it could lead to unauthorized access and potential security risks.

## Description

The detector performs the following checks:
- Attempts to access the Flowise UI endpoint
- Verifies if the API interface is accessible without authentication

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
