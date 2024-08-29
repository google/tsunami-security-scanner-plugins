# CVE-2023-23752 VulnDetector

An issue was discovered in Joomla! 4.0.0 through 4.2.7. An improper access check allows unauthorized access to
webservice endpoints.

- https://nvd.nist.gov/vuln/detail/CVE-2023-23752
- https://huntr.dev/bounties/a10cb87b-f425-43a7-af6f-1d2d6c896ac7

This vulnerability can lead to RCE if you expose your Joomla DB server to outside, Also if administrator use same
password other places, Attackers can leverage leaked credentials to login in other services.
For detailed information please read following reference.

- https://vulncheck.com/blog/joomla-for-rce

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.