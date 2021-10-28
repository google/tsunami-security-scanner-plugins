# CVE-2021-29441 VulnDetector

This detector checks for Nacos < 1.4.1 Authentication Bypass and disclosure vulnerability (CVE-2021-29441).
When configured to use authentication (-Dnacos.core.auth.enabled=true) Nacos uses the AuthFilter servlet filter to enforce authentication. This filter has a backdoor that enables Nacos servers to bypass this filter and therefore skip authentication checks. This mechanism relies on the user-agent HTTP header so it can be easily spoofed.
This issue is known to be exploited in the wild.
This issue is for Nacos <1.4.1 versions.
https://github.com/advisories/GHSA-36hp-jr8h-556f
https://nvd.nist.gov/vuln/detail/CVE-2021-29441


## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
