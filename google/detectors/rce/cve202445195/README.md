# CVE-2024-45195 Detector

This detector identifies instances of Apache OFBiz vulnerable to
[CVE-2024-45195](https://nvd.nist.gov/vuln/detail/CVE-2024-45195), an
unauthenticated remote code execution issue affecting Apache OFBiz prior to
version `18.12.16` (CVSS 9.8, Critical).

## Vulnerability

CVE-2024-45195 is the third patch bypass in a chain that also includes
CVE-2024-32113, CVE-2024-36104, and CVE-2024-38856. The underlying flaw is a
controller/view-map state desynchronization in the OFBiz request handler: the
controller resolves authentication against the first path segment (a public
view such as `forgotPassword`) while the screen renderer honors the last
segment (a privileged view such as `ProgramExport`). An unauthenticated
attacker can therefore render admin-only Groovy screens and execute arbitrary
code on the server.

The distinguishing signature of CVE-2024-45195 is a direct request of the form
`POST /webtools/control/forgotPassword/<PrivilegedView>` — no path traversal
(that is CVE-2024-32113) and no `main/<view>` chain (that is CVE-2024-38856).
A target patched for those earlier CVEs but not for CVE-2024-45195 will still
be flagged by this detector.

## Detection strategy

The detector sends a single request:

```
POST /webtools/control/forgotPassword/ProgramExport HTTP/1.1
Content-Type: application/x-www-form-urlencoded

groovyProgram=throw+new+Exception('<PAYLOAD>'.execute().text);
```

The `<PAYLOAD>` value is produced by Tsunami's `PayloadGenerator`
(`REFLECTIVE_RCE` / `LINUX_SHELL` / `EXEC_INTERPRETATION_ENVIRONMENT`). On a
vulnerable server the Groovy expression is executed, the resulting shell
command runs, and its output is reflected inside a `java.lang.Exception:`
error block in the rendered HTML. The detector considers the target vulnerable
iff `Payload.checkIfExecuted(responseBody)` returns `true`.

Patched servers respond with the login page (unauthenticated `forgotPassword`
flow) and do not reflect the payload, so no report is emitted.

## References

- NVD: <https://nvd.nist.gov/vuln/detail/CVE-2024-45195>
- Rapid7 advisory / analysis:
  <https://www.rapid7.com/blog/post/2024/09/05/cve-2024-45195-apache-ofbiz-unauthenticated-remote-code-execution-fixed/>
- Apache OFBiz framework patch commit:
  <https://github.com/apache/ofbiz-framework/commit/ab78769c2d>
- Apache OFBiz plugins patch commit:
  <https://github.com/apache/ofbiz-plugins/commit/8b95fe6fa>
- Vulhub PoC environment:
  <https://github.com/vulhub/vulhub/tree/master/ofbiz/CVE-2024-45195>

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

The Tsunami-identifiable jar file is written to `build/libs/`.

## Testing

Unit tests use `MockWebServer` and `FakePayloadGeneratorModule` with a fixed
`SecureRandom` so the framed `PayloadGenerator` token is deterministic. Three
cases are covered:

1. Vulnerable OFBiz — server reflects the framed exception; detector reports
   `VULNERABILITY_VERIFIED`.
2. Benign 200 response — detector reports nothing.
3. Patched OFBiz login page — detector reports nothing (false-positive guard).


Run the tests with:

```shell
./gradlew test
```
