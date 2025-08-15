# Uptrain Exposed API Detector

This detector checks for an exposed Uptrain API service by attempting to create
a project with a malicious AI Model, which can lead to remote code execution
(RCE) on the server.

The Uptrain API requires authentication by default using a constant key.
However, a common misconfiguration involves using the default key, allowing
anyone to exploit the API.

## How it works

1.  The detector sends a request to the Uptrain API to check if it is accessible
    with default authentication key.
2.  If accessible, it sends a payload to create a project with a malicious AI
    Model.
3.  The detector waits for a callback to confirm if the RCE was successful.

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar

Tsunami identifiable jar file is located at `build/libs` directory.
```
