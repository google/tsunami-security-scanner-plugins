# CVE-2021-40539 VulnDetector

This detector checks for ADSelfService Plus REST API Authentication Bypass (RCE)  vulnerability (CVE-2021-40539).
Zoho ManageEngine ADSelfService Plus version 6113 and prior is vulnerable to REST API authentication bypass with resultant remote code execution.

- https://www.manageengine.com/products/self-service-password/kb/how-to-fix-authentication-bypass-vulnerability-in-REST-API.html
- https://www.manageengine.com/products/self-service-password/release-notes.html
- https://www.synacktiv.com/publications/how-to-exploit-cve-2021-40539-on-manageengine-adselfservice-plus.html
- https://www.rapid7.com/db/vulnerabilities/zoho-manageengine-adselfservice-plus-cve-2021-40539/

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
