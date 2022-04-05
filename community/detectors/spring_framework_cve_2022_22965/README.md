# Spring Framework RCE CVE-2022-22965

A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding.
The specific exploit requires the application to run on Tomcat as a WAR deployment.
If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit.
However, the nature of the vulnerability is more general, and there may be other ways to exploit it.
Users of affected versions should apply the following mitigation: 5.3.x users should upgrade to 5.3.18+, 5.2.x users should upgrade to 5.2.20+.
https://tanzu.vmware.com/security/cve-2022-22965
https://spring.io/blog/2022/03/31/spring-framework-rce-early-announcement
https://mp.weixin.qq.com/s/BnF8CWuUxNliCoa260bEaA

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
