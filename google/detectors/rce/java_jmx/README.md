# Java Unprotected JMX Server Detector

This detector checks for unprotected Java JMX server with RMI endpoint, which
allows remote users running arbitrary code on the server. See https://nvd.nist.gov/vuln/detail/CVE-2019-12409
and https://nsfocusglobal.com/apache-solr-remote-code-execution-vulnerability-cve-2019-12409-threat-alert/.

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
