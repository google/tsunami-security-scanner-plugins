# Microsoft Exchange ProxyLogon SSRF and RCE (CVE-2021-26855)

## Description

The Microsoft Exchange Server contains mishandles cookies and headers sent, allowing Server-Side Request Forgery and ultimately Remote Code Execution when combined with other vulnerabilities for the same server version. The vulnerability detected is the original unauthenticated Server-Side Request Forgery vulnerability (CVE-2021-26855).

This plugin requires a DNS callback server to receive the interaction.

## Affected Versions

-   Exchange 2013 Versions < 15.00.1497.012
-   Exchange 2016 CU18 < 15.01.2106.013
-   Exchange 2016 CU19 < 15.01.2176.009
-   Exchange 2019 CU7 < 15.02.0721.013
-   Exchange 2019 CU8 < 15.02.0792.010

## References

-   [Vulhub](https://github.com/vulhub/vulhub/tree/master/fastjson/1.2.47-rce)
-   [NIST](https://nvd.nist.gov/vuln/detail/cve-2021-26855)

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

The Tsunami identifiable jar file is located at `build/libs` directory.
