# CVE-2021-41773 VulnDetector utilizing the payload generation framework

This plugin for Tsunami detects the RCE part of the vuln CVE-2021-41773, which
consists of a path traversal and a RCE vulnerability.

More information on the vulnerability:

* [CVE-2021-41773](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-41773)
* [POC](https://github.com/iilegacyyii/PoC-CVE-2021-41773)
* [Vulnerable Docker images used for testing](https://github.com/BlueTeamSteve/CVE-2021-41773)
* [Another Docker images for testing](https://github.com/blasty/CVE-2021-41773)

<!-- TODO(andreasgeiger): enrich infos -->

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
