# CVE-2023-22893 VulnDetector

Strapi through 4.5.5 does not verify the access or ID tokens issued during the
OAuth flow when the AWS Cognito login provider is used for authentication. A
remote attacker could forge an ID token that is signed using the 'None' type
algorithm to bypass authentication and impersonate any user that use AWS Cognito
for authentication. with the help of CVE-2023-22621 and CVE-2023-22894 attackers
can gain Unauthenticated Remote Code Execution on these versions of Strapi.

-   https://www.ghostccamm.com/blog/multi_strapi_vulns
-   https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-22893

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
