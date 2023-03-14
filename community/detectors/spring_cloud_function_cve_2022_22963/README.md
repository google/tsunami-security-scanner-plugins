# Spring Cloud Function CVE-2022-22963 VulnDetector

In Spring Cloud Function versions 3.1.6, 3.2.2 and older unsupported versions, when using routing functionality it is possible for a user to provide a specially crafted SpEL as a routing-expression that may result in remote code execution and access to local resources.

- https://github.com/spring-cloud/spring-cloud-function/commit/0e89ee27b2e76138c16bcba6f4bca906c4f3744f
- https://github.com/cckuailong/spring-cloud-function-SpEL-RCE
- https://tanzu.vmware.com/security/cve-2022-22963
- https://nsfocusglobal.com/spring-cloud-function-spel-expression-injection-vulnerability-alert/
- https://github.com/vulhub/vulhub/tree/scf-spel/spring/spring-cloud-function-spel-injection

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
