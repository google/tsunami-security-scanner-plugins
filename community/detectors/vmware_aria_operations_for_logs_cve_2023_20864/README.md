# vmware aria operations for logs RCE Detector

### CVE

[CVE-2023-20864](https://github.com/advisories/GHSA-8xj6-cxx5-jf7j)

### Description of Vulnerability

VMware Aria Operations for Logs (formerly vRealize Log Insight) contains a deserialization vulnerability. An
unauthenticated, malicious actor with network access to VMware Aria Operations
for Logs may be able to execute arbitrary code as root.

The affected version is 8.10.2, it is recommended to upgrade to 8.12

##### Related Articles:

https://www.zerodayinitiative.com/blog/2023/6/29/cve-2023-20864-remote-code-execution-in-vmware-aria-operations-for-logs

https://github.com/advisories/GHSA-8xj6-cxx5-jf7j

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.

--------------------------------------------------------------------------------

