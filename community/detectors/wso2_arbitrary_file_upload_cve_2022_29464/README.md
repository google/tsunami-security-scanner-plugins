# WSO2 products CVE-2022-29464 Detector

This detector checks for WSO2 Unrestricted Arbitrary File Upload
(CVE-2022-29464). Due to improper validation of user input, a malicious actor
could upload an arbitrary file to a user controlled location of the server. By
leveraging the arbitrary file upload vulnerability, it is further possible to
gain remote code execution on the server. This issue is known to be exploited in
the wild.
https://docs.wso2.com/display/Security/Security+Advisory+WSO2-2021-1738

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
