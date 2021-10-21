# Apache Solr RemoteStreaming Arbitrary File Reading and SSRF Detector

This detector checks for Apache Solr Arbitrary File Reading and SSRF in unauthenticated. Apache Solr
is an open source search server. When Apache Solr does not enable authentication, an attacker can
directly craft a request to enable a specific configuration, and eventually cause SSRF or arbitrary
file reading.

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
