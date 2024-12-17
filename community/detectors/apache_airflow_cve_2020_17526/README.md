# Apache Airflow CVE-2020-17526 Detector

This plugin for Tsunami detects a remote code execution (RCE) vulnerability in a
default DAG of apache airflow UI with the help of CVE-2020-17526, which is an
authentication bypass vulnerability.

More information on the vulnerability:

*   [CVE-2020-17526](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-17526)

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
