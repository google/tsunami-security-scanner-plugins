# Node-RED-Dashboard Directory Traversal Detector (CVE 2021-3223)

This Tsunami plugin tests to see if the traversal of `ui_base/js/..%2f` directory is vulnerable to remote attackers, allowing them to read arbitrary files.

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
