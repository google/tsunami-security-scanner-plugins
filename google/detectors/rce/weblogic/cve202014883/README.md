# Oracle WebLogic Admin Console RCE Detector

This detector checks for [CVE-2020-14750](https://nvd.nist.gov/vuln/detail/CVE-2020-14750),
[CVE-2020-14882](https://nvd.nist.gov/vuln/detail/CVE-2020-14882),
[CVE-2020-14883](https://nvd.nist.gov/vuln/detail/CVE-2020-14883)
vulnerabilities in Oracle WebLogic Admin Console. It covers WebLogic 12.2.1 and
above that contains `com.tangosol.coherence.mvel2.sh.ShellSession` class.

This detector works with and without callback server, and uses a different payload
for each mode.

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
