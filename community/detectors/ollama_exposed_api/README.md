# Exposed Ollama API Server Detector

This plugin for Tsunami detects publicly exposed Ollama API Servers. First
it tries to identify an Ollama API server by accessing its' default landing page.
Afterwards it tries to retrieve a list of existing Ollama models to verify that the API can be used by an unauthenticated attacker.

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
