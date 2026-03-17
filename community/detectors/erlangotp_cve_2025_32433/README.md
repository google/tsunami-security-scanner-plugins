# Erlang/OTP SSH Server CVE-2025-32433 RCE Detector

This detector checks for Remote Code Execution (RCE) vulnerability in Erlang/OTP
SSH servers (CVE-2025-32433). A command injection flaw in the SSH subsystem
allows unauthenticated attackers to execute arbitrary commands by sending
crafted SSH messages to affected Erlang/OTP versions.

## References

-   https://github.com/erlang/otp/security/advisories/GHSA-37cp-fgq5-7wc2
-   https://nvd.nist.gov/vuln/detail/CVE-2025-32433

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
