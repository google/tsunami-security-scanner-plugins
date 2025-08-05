# Grafana api_jsonrpc.php Zabbix Credential Disclosure (CVE-2022-26148)

## Description

Grafana v7.3.4 and earlier versions are vulnerable to a critical unauthenticated
Credential Disclosure vulnerability. This flaw allows attackers to obtain
sensitive Zabbix credentials by simply inspecting the HTML source code of
Grafana's welcome page. Not every Grafana service is vulnerable, to see the
Zabbix `password` in the html response this configuration must be in place: the
Grafana instances must have Zabbix integration enabled and the Zabbix passwords
must have been stored insecurely in the `jsonData` object instead of the secure
`secureJsonData` object.

### Impact

The vulnerability can be exploited to gain administrative access over the Zabbix
server (in earlier versions, full URL to `api_jsonrpc.php` is also present in
the HTML response). This will result in the Zabbix URL to be disclosed to the
attacker.

### Detector's implementation

The detector simply sends requests to known vulnerable endpoints and analyzes
the responses searching for Zabbix credentials. An optional exploitation step
(not implemented) could involve also extracting the `api_jsonrpc.php` URL and
attempting to use the Zabbix credentials on the frontend (which would also be
exposed in the same URL).

## Affected Versions

-   v7.3.4 and earlier versions

*These versions are vulnerable only if the Grafana-Zabbix integration is
installed and configured as outlined above

## References

-   [Grafana api_jsonrpc.php Zabbix Credentials Disclosure (CVE-2022-26148)](https://nvd.nist.gov/vuln/detail/cve-2022-26148)

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
