# PostgresQL CVE-2019-9193 Detector

This plugin for Tsunami detects a postgres remote code execution (RCE)
caused by default credentials and "COPY..FROM".

More information on the vulnerability:

* [CVE-2019-9193](https://medium.com/greenwolf-security/authenticated-arbitrary-command-execution-on-postgresql-9-3-latest-cd18945914d5)

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
