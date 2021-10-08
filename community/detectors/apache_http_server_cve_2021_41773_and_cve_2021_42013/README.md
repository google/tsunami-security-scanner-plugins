# Apache HTTP Server 2.4.49 CVE-2021-41773 Path traversal and disclosure vulnerability Detector

This detector checks for Apache HTTP Server 2.4.49 Path traversal and disclosure vulnerability (CVE-2021-41773).
A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the expected document root.
If files outside of the document root are not protected by "require all denied" these requests can succeed. Additionally this flaw could leak the source of interpreted files like CGI scripts.
This issue is known to be exploited in the wild.
This issue only affects Apache 2.4.49 and not earlier versions.
https://httpd.apache.org/security/vulnerabilities_24.html
https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-41773

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
