# Atlassian Bitbucket DC RCE (CVE-2022-26133)" Detector

Atlassian Bitbucket Data Center versions 5.14.0 and later before
7.6.14, 7.7.0 and later prior to 7.17.6, 7.18.0 and later prior
to 7.18.4, 7.19.0 and later prior to 7.19.4, and 7.20.0 allow a
remote, unauthenticated attacker to execute arbitrary code via
Java deserialization vulnerability inside SharedSecretClusterAuthenticator.

See https://github.com/snowyyowl/writeups/tree/main/CVE-2022-26133 for a details.

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```
