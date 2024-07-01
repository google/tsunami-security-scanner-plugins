# XWiki RCE CVE-2024-21650 Detector

XWiki Platform is a generic wiki platform offering runtime services for applications built on top of
it. XWiki is vulnerable to a remote code execution (RCE) attack through its user registration
feature. This issue allows an attacker to execute arbitrary code by crafting malicious payloads in
the "first name" or "last name" fields during user registration. This impacts all installations that
have user registration enabled for guests. This vulnerability has been patched in XWiki 14.10.17,
15.5.3 and 15.8 RC1.
See https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-21650 for a details.

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```
