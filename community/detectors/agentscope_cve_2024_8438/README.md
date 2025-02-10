# Agentscope Studio Arbitrary File Download Detector

This plugin for Tsunami detects publicly exposed agentscope studio instances. The /api/file endpoint in modelscope/agentscope is vulnerable to Arbitrary File Download, allowing attackers to retrieve internal files without restriction. This could lead to the unintended exposure of sensitive information, including configuration files that contain database credentials.

References:
- https://huntr.com/bounties/3f170c58-42ee-422d-ab6f-32c7aa05b974

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
