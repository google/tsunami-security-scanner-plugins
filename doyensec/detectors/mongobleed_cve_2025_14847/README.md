# MongoBleed CVE-2025-14847 Detector

This plugin for Tsunami detects a vulnerability which enables uninitialized heap memory read by an unauthenticated client in MongoDB.

This issue affects all MongoDB Server v7.0 prior to 7.0.28 versions, MongoDB Server v8.0 versions prior to 8.0.17, MongoDB Server v8.2 versions prior to 8.2.3, MongoDB Server v6.0 versions prior to 6.0.27, MongoDB Server v5.0 versions prior to 5.0.32, MongoDB Server v4.4 versions prior to 4.4.30, MongoDB Server v4.2 versions greater than or equal to 4.2.0, MongoDB Server v4.0 versions greater than or equal to 4.0.0, and MongoDB Server v3.6 versions greater than or equal to 3.6.0.

More information on the vulnerability:

- [CVE-2025-14847](https://nvd.nist.gov/vuln/detail/CVE-2025-14847)
- [POC](https://github.com/joe-desimone/mongobleed/blob/main/README.md)

## Build jar file for this plugin

Using `gradle`:

```shell
gradle jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
