# Roxy-wi RCE CVE-2022-31137 Detector

Roxy-WI is a web interface for managing Haproxy, Nginx, Apache and Keepalived
servers. Versions prior to `6.1.1.0` are subject to a remote code execution
vulnerability. System commands can be run remotely via the `subprocess_execute`
function without processing the inputs received from the user in the
/app/options.py file. Authentication is not required to exploit this
vulnerability. Users are advised to upgrade. There are no known workarounds for
this vulnerability.

See https://nvd.nist.gov/vuln/detail/CVE-2022-31137 for a details.

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```
