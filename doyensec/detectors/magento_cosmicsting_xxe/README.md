# Magento / Adobe Commerce CosmicSting XXE (CVE-2024-34102)

## Description

Adobe Commerce and Magento v2.4.7 and earlier are vulnerable to a critical
unauthenticated XXE (XML External Entity) vulnerability that can lead to
arbitrary code execution on unpatched systems. The vulnerability can be
exploited by sending an unauthenticated HTTP request with a crafted XML file
that references external entities; when the request payload is deserialized, the
attacker can extract sensitive files from the system and gain administrative
access to the software.

### Impact

The CosmicSting XXE vulnerability by itself can be exploited to perform
Arbitrary File Reads and Server-Side Request Forgeries (SSRF). Effectively, this
allows attackers to leak sensitive information from files in the target system
or from internal network endpoints. For example, an attacker could leak
Magento's configuration files to gain administrative access to the software, or
leak an SSH key to log onto the system itself.

### Remote Code Execution

On unpatched systems, Remote Code Execution can be achieved by combining the
CosmicSting XXE vulnerability with the
[PHP iconv RCE](https://www.ambionics.io/blog/iconv-cve-2024-2961-p1) (aka
CNEXT). A very reliable public exploit for Magento that leverages both
vulnerabilities and achieves RCE was released by @cfreal, the author of the
iconv research, and can be found
[here](https://github.com/ambionics/cnext-exploits/blob/main/cosmicsting-cnext-exploit.py).

### Detector's implementation

This detector only exploits the XXE vulnerability to perform a simple Arbitrary
File Read (leaking `/etc/passwd`) and a SSRF (calling back to the Tsunami
Callback Server). It was not possible to implement the full RCE exploit due to
the current limitations of the Callback Server. Specifically, the RCE exploit
requires leaking the process memory map and the system's libc binary, in order
to properly calculate the memory addresses needed for the final exploit step.
Even if the Callback Server allows us to check whether a callback was received,
it doesn't allow us to fetch any extra data attached to the request (such as URL
parameters or the POST body), thus it makes it impossible for us to retrieve the
leaked data needed for the full exploit.

## Affected Versions

-   2.4.7 and earlier
-   2.4.6-p5 and earlier
-   2.4.5-p7 and earlier
-   2.4.4-p8 and earlier
-   2.4.3-ext-7 and earlier*
-   2.4.2-ext-7 and earlier*

*These versions are only applicable to customers participating in the Extended
Support Program

## References

-   [CosmicSting: critical unauthenticated XXE vulnerability in Adobe Commerce
    and Magento
    (CVE-2024-34102)](https://www.vicarius.io/vsociety/posts/cosmicsting-critical-unauthenticated-xxe-vulnerability-in-adobe-commerce-and-magento-cve-2024-34102)
-   [NIST: CVE-2024-34102](https://nvd.nist.gov/vuln/detail/CVE-2024-34102)
-   [Adobe Security Bulletin APSB24-40](https://helpx.adobe.com/security/products/magento/apsb24-40.html)
-   [CosmicSting CNEXT RCE exploit](https://github.com/ambionics/cnext-exploits/blob/main/cosmicsting-cnext-exploit.py)

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

The Tsunami identifiable jar file is located at `build/libs` directory.
