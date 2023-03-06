# CVE-2019-20933 VulnDetector

InfluxDB before 1.7.6 has an authentication bypass vulnerability in the authenticate function in
services/httpd/handler.go because a JWT token may have an empty SharedSecret (aka shared secret).

- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-20933

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
