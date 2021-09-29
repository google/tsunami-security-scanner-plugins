# Apache Flink CVE-2020-17519 Detector

This plugin detects a directory traversal vulnerability in Apache Flink that
can be used for unauthorized reads on files on the filesystem, to the extent
permitted for the JobManager process.

More information on the vulnerability:

* [CVE-2020-17519](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-17519)
* https://nvd.nist.gov/vuln/detail/CVE-2020-17519

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
