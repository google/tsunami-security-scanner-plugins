# Apache Tomcat CVE-2017-12617 RCE Detector

This plugin detects CVE-2017-12617, an Apache Tomcat RCE via the upload of
arbitrary JSP files.

Initially the vulnerability was found in the context of windows
(CVE-2017-12615), and later it was discovered as a more widespread issue,
affecting all operating systems that run Apache Tomcat with vulnerable versions
(CVE-2017-12617).

## Details

Vulnerable tomcat instances containing a servlet context configured with
`readonly=false` within the `web.xml` configuration, allow unauthenticated
actors to upload arbitrary JSP files to the server via a specially crafted
request. The uploaded JSP file could then be requested and any code it contained
would be executed by the server, leading to Remote Code Execution (RCE).

Given a vulnerable instance of Tomcat, it is possible to upload an abitrary JSP
file by performing a PUT request at the following URI:
`http://<tomcat_host>:8080/1.jsp/`. Notice that the final `/` at the end of the
URI is what bypasses the normal checks that should ensure that no JSP file can
be uploaded.

As a remediation strategy, it is suggested to patch vulnerable versions, and to
ensure that readonly is set to true for the default servlet and for the webdav
servlet.

**Affected Versions of Apache Tomcat**

7.0.0 to 7.0.81 8.0.0 RC1 to 8.0.46 8.5.0 to 8.5.22 9.0.0 M1 to 9.0.0

## References

*   https://nvd.nist.gov/vuln/detail/cve-2017-12617
*   https://www.exploit-db.com/exploits/42966
*   https://nvd.nist.gov/vuln/detail/cve-2017-12615
*   https://breaktoprotect.blogspot.com/2017/09/the-case-of-cve-2017-12615-tomcat-7-put.html

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
