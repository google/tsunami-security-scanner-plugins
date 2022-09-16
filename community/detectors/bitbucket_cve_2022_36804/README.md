# BitBucket CVE-2022-36804 command injection vulnerability Detector

This detector checks for BitBucket CVE-2022-36804 command injection vulnerability.

A vulnerability in Bitbucket allows a remote, An attacker with access 
    to a public Bitbucket repository or with read permissions to a
    private one can execute arbitrary code by sending a malicious 
    HTTP request. This All versions released after 6.10.17 
    including 7.0.0 and newer are affected, this means that all 
    instances that are running any versions between 7.0.0 and 
    8.3.0 inclusive can be exploited by this vulnerability.

https://jira.atlassian.com/browse/BSERV-13438

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.