# RocketMQ CVE-2023-33246 Detector

This plugin for Tsunami detects a critical remote code execution (RCE) vulnerability in Apache RocketMQ. CVE-2023-33246 allows a remote and unauthenticated attacker to update the RocketMQ broker configuration and inject malicious commands through a command injection vulnerability.

Exploitation occurs by using a custom remoting protocol on RocketMQ broker ports (typically 10909 and 10911). Attackers can update the broker configuration and inject payloads that are executed when the configuration is parsed. This vulnerability persists in the configuration file unless overwritten, making it a severe and exploitable issue.

More information on the vulnerability:
* [CVE-2023-33246](https://nvd.nist.gov/vuln/detail/CVE-2023-33246)
* [RocketMQ Exploit Payloads](https://vulncheck.com/blog/rocketmq-exploit-payloads)

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
