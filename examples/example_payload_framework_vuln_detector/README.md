# Example VulnDetector utilizing the payload generation framework

This is an example implementation of a `VulnDetector` plugin for Tsunami that
uses Tsunami's optional payload generation framework. This framework is designed
to automatically select the best payload for a detector, taking out the
guesswork when writing a new detector and reducing false positives. If
configured, the framework will automatically utilize the
[Tsunami Callback Server](https://github.com/google/tsunami-security-scanner-callback-server),
which helps further validate findings.

Detectors targeting remote code executions (RCE) and server-side request forgery
(SSRF) vulnerabilities are ideal candidates for using the payload framework.

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
