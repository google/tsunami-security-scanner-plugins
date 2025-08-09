# Synacor Zimbra Collaboration Suite XXE CVE-2019-9670

This plugin detects CVE-2019-9670, an XXE vulnerability affecting Synacor Zimbra
Collaboration Suite.

## Details

The XXE affects the mailboxd component of Synacor Zimbra Collaboration Suite and
it is found in the autodiscover feature, available to unauthenticated users
through the endpoint `/Autodiscover/Autodiscover.xml`. The vulnerability allows
malicious actors to extract sensitive files from the system and can be chained
with another vulnerability (CVE-2019-9621) in order to obtain an unauthenticated
RCE.

Specifically, by using the XXE (CVE-2019-9670) it is possible to read a
configuration file that contains an LDAP password for the zimbra account. The
zimbra credentials are then used to get a user authentication cookie with an
AuthRequest message. Using the user cookie, a SSRF (CVE-2019-9621) in the Proxy
Servlet is used to proxy an AuthRequest with the zimbra credentials to the admin
port to retrieve an admin cookie. After gaining an admin cookie the Client
Upload servlet is used to upload a JSP webshell that can be triggered from the
web server to obtain RCE.

**Affected Versions** from 8.5 to 8.7.11p10

## References

*   https://nvd.nist.gov/vuln/detail/cve-2019-9670
*   https://blog.tint0.com/2019/03/a-saga-of-code-executions-on-zimbra.html
*   https://blog.zimbra.com/2019/03/new-zimbra-8-7-11-patch-10/
*   https://attackerkb.com/topics/7bMNsBStux/zimbra-collaboration-suite-autodiscover-xxe/vuln-details

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
