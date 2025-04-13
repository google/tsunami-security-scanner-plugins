# Ray CVE-2023-6019 Detector

This plugin for Tsunami detects a remote code execution (RCE) vulnerability in Ray, which is an ML platform.

More information on the vulnerability:

* [CVE-2023-6019](https://nvd.nist.gov/vuln/detail/CVE-2023-6019)
* [POC](https://github.com/protectai/ai-exploits/blob/main/ray/nuclei-templates/ray-cpuprofile-cmd-injection.yaml)

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
