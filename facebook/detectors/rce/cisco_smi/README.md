# Cisco SMI Protocol Detector

This detector checks whether the Cisco Smart Install Protocol is exposed and
vulnerable to misuses.

https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170214-smi
https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180328-qos
https://github.com/Cisco-Talos/smi_check/blob/master/smi_check.py

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
