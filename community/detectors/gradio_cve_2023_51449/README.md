# Gradio CVE-2023-51449 File Traversal Vulnerability

This detector checks for Gradio CVE-2023-51449 File Traversal Vulnerability.

Older versions of `gradio` contained a vulnerability in the `/file` route which
made them susceptible to file traversal attacks in which an attacker could
access arbitrary files on a machine running a Gradio app with a public URL (e.g.
if the demo was created with share=True, or on Hugging Face Spaces) if they knew
the path of files to look for. This was not possible through regular URLs passed
into a browser, but it was possible through the use of programmatic tools such
as `curl` with the `--pass-as-is` flag. Furthermore, the `/file` route in Gradio
apps also contained a vulnerability that made it possible to use it for SSRF
attacks. Both of these vulnerabilities have been fixed in `gradio==4.11.0`.

-   https://github.com/gradio-app/gradio/security/advisories/GHSA-6qm2-wpxq-7qh2
-   https://nvd.nist.gov/vuln/detail/CVE-2023-51449

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
