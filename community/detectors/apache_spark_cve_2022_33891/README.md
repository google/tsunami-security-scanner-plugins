# Apache Spark UI CVE-2022-33891 RCE Vulnerability Detector

This detector checks for Apache Spark UI CVE-2022-33891 RCE vulnerability.

The Apache Spark UI offers the possibility to enable ACLs via the configuration
option spark.acls.enable. With an authentication filter, this checks whether a
user has access permissions to view or modify the application. If ACLs are
enabled, a code path in HttpSecurityFilter can allow someone to perform
impersonation by providing an arbitrary user name. A malicious user might then
be able to reach a permission check function that will ultimately build a Unix
shell command based on their input, and execute it. This will result in
arbitrary shell command execution as the user Spark is currently running as.
This affects Apache Spark versions 3.0.3 and earlier, versions 3.1.1 to 3.1.2,
and versions 3.2.0 to 3.2.1.

-   https://spark.apache.org/security.html#CVE-2022-33891
-   https://nvd.nist.gov/vuln/detail/cve-2022-33891

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
