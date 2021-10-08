# Apache HTTP Server CVE-2021-41773 and CVE-2021-42013 Path traversal and RCE vulnerability Detector

This detector checks for Apache HTTP Server CVE-2021-41773 and CVE-2021-42013 Path traversal and RCE vulnerability (CVE-2021-41773 and CVE-2021-42013).

## CVE-2021-41773

A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the expected document root.
If files outside of the document root are not protected by "require all denied" these requests can succeed. Additionally this flaw could leak the source of interpreted files like CGI scripts.
This issue is known to be exploited in the wild.
This issue only affects Apache 2.4.49 and not earlier versions.
https://httpd.apache.org/security/vulnerabilities_24.html
https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-41773

## CVE-2021-41773

It was found that the fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 was insufficient. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives.

If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution.

This issue only affects Apache 2.4.49 and Apache 2.4.50 and not earlier versions.

https://httpd.apache.org/security/vulnerabilities_24.html
https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-42013

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
