# WebLogic CVE-2020-14882 Detector

This probe can bypass the permission verification of the weblogic management console. Command
execution can be performed if the management console permission is obtained.
https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-14882
https://nvd.nist.gov/vuln/detail/CVE-2020-14882

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
