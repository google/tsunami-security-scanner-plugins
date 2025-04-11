# CVE-2022-22954 VulnDetector

This detector checks for VMware Workspace ONE Access and Identity Manager Server-side Template Injection Remote Code Execution Vulnerability (CVE-2022-22954).
VMware Workspace ONE Access and Identity Manager contain a remote code execution vulnerability due to server-side template injection. A malicious actor with network access can trigger a server-side template injection that may result in remote code execution.

https://www.vmware.com/security/advisories/VMSA-2022-0011.html
https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22954
https://exchange.xforce.ibmcloud.com/vulnerabilities/223514


## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
