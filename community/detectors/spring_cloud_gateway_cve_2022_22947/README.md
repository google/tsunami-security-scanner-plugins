# CVE-2022-22947 VulnDetector

This detector checks for Spring Cloud Gateway Actuator API SpEL Code Injection vulnerability (CVE-2022-22947).
In spring cloud gateway versions prior to 3.1.1+ and 3.0.7+ , applications are vulnerable to a code injection attack when the Gateway Actuator endpoint is enabled, exposed and unsecured. A remote attacker could make a maliciously crafted request that could allow arbitrary remote execution on the remote host.

- https://spring.io/blog/2022/03/01/spring-cloud-gateway-cve-reports-published
- https://wya.pl/2022/02/26/cve-2022-22947-spel-casting-and-evil-beans/
- https://tanzu.vmware.com/security/cve-2022-22947


## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
