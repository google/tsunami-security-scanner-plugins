# h2o CVE-2023-6018 Detector

This plugin for Tsunami detects a remote code execution (RCE) vulnerability in
h2o, which is an ML platform.

More information on the vulnerability:

* [CVE-2023-6018](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-6018)
* [POC](https://github.com/protectai/ai-exploits/blob/main/h2o/nuclei-templates/h2o-pojo-rce.yaml)

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
