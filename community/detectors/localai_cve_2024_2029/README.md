# LocalAI CVE-2024-2029 RCE Detector

This Tsunami plugin tests to see if the LocalAI Instances are vulnerable to CVE-2024-2029 or not.
Publicly exposed LocalAI instances that are vulnerable to this CVE can lead to 
Remote Code Execution Vulnerability by attackers.

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
