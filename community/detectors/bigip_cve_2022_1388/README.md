# CVE-2022-1388 VulnDetector

On F5 BIG-IP 16.1.x versions prior to 16.1.2.2, 15.1.x versions prior to 15.1.5.1, 14.1.x versions prior to 14.1.4.6, 13.1.x versions prior to 13.1.5, and all 12.1.x and 11.6.x versions, undisclosed requests may bypass iControl REST authentication.

- https://nvd.nist.gov/vuln/detail/CVE-2022-1388
- https://packetstormsecurity.com/files/167007/F5-BIG-IP-Remote-Code-Execution.html
- https://support.f5.com/csp/article/K23605346


## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
