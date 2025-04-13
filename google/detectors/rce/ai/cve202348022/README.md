# ray CVE-2023-48022 Detector

This plugin for Tsunami detects a remote code execution (RCE) vulnerability in
ray, which is an ML platform.

More information on the vulnerability:

* [CVE-2023-48022](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-48022)
* [POC](https://github.com/protectai/ai-exploits/blob/main/ray/nuclei-templates/ray-job-rce.yaml)

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
