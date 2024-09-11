# MLflow LFI CVE-2024-2928 Detector

A Local File Inclusion (LFI) vulnerability was identified in
mlflow, which was fixed in version 2.11.2. This
vulnerability arises from the application's failure to properly
validate URI fragments for directory traversal sequences such
as '../'. An attacker can exploit this flaw by manipulating the
fragment part of the URI to read arbitrary files on the local
file system, including sensitive files like '/etc/passwd'. The
vulnerability is a bypass to a previous patched vulnerability
(namely for CVE-2023-6909) that only addressed similar
manipulation within the URI's query string.

-   https://huntr.com/bounties/19bf02d7-6393-4a95-b9d0-d6d4d2d8c298
-   https://nvd.nist.gov/vuln/detail/CVE-2024-2928

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
