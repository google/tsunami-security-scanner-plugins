# Magento / Adobe Commerce CosmicSting XXE (CVE-2024-34102)

## Description
Adobe Commerce and Magento v2.4.7 and earlier are vulnerable to a critical unauthenticated XXE (XML External Entity) vulnerability that could allow arbitrary code execution. The vulnerability can be exploited by sending an unauthenticated HTTP request with a crafted XML file that references external entities; when the request payload is deserialized, the attacker can extract sensitive files from the system and gain administrative access to the software. Remote Code Execution (RCE) could be accomplished by combining the issue with another vulnerability, such as the [PHP iconv RCE](https://www.ambionics.io/blog/iconv-cve-2024-2961-p1).

## Affected Versions
- 2.4.7 and earlier
- 2.4.6-p5 and earlier
- 2.4.5-p7 and earlier
- 2.4.4-p8 and earlier
- 2.4.3-ext-7 and earlier*
- 2.4.2-ext-7 and earlier*

*These versions are only applicable to customers participating in the Extended Support Program

## References
- [CosmicSting: critical unauthenticated XXE vulnerability in Adobe Commerce and Magento (CVE-2024-34102)](https://www.vicarius.io/vsociety/posts/cosmicsting-critical-unauthenticated-xxe-vulnerability-in-adobe-commerce-and-magento-cve-2024-34102)
- [NIST: CVE-2024-34102](https://nvd.nist.gov/vuln/detail/CVE-2024-34102)
- [Adobe Security Bulletin APSB24-40](https://helpx.adobe.com/security/products/magento/apsb24-40.html)

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

The Tsunami identifiable jar file is located at `build/libs` directory.