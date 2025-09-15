# Apache Solr Unsafe Deserialization (CVE-2019-0192)

## Description

In Apache Solr versions 5.0.0 to 5.5.5 and 6.0.0 to 6.6.5, the Config API allows
attackers to configure the JMX server via an HTTP POST request. By directing it
to a malicious RMI server, this vulnerability can be exploited to trigger unsafe
deserialization, leading to remote code execution on the Solr server.

## Affected Versions

-   5.0.0 to 5.5.5
-   6.0.0 to 6.6.5

## References

-   [Redhat Advisory](https://access.redhat.com/security/cve/CVE-2019-0192)
-   [Bug Tracker](https://bugzilla.redhat.com/show_bug.cgi?id=1692345)

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

The Tsunami identifiable jar file is located at `build/libs` directory.
