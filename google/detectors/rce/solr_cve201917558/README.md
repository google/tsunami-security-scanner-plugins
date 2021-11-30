# Apache Solr VelocityResponseWriter RCE Detector (CVE-2019-17558)

This detector finds CVE-2019-17558 remote code execution in unauthenticated
Apache Solr deployments. See https://nvd.nist.gov/vuln/detail/CVE-2019-17558.

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
