# Gradio LFI CVE-2024-1728 Detector

Gradio is vulnerable to a Local File Inclusion vulnerability, which was fixed in
version 4.19.2, due to improper validation of user-supplied input in the
UploadButton component. While the component handles file upload paths, it
unintentionally allows attackers to redirect file uploads to arbitrary locations
on the server. After this path change, attackers can exploit this vulnerability
to read arbitrary files on the filesystem, such as private SSH keys, by
manipulating the file path in the request to the /queue/join endpoint.

-   https://huntr.com/bounties/9bb33b71-7995-425d-91cc-2c2a2f2a068a
-   https://nvd.nist.gov/vuln/detail/CVE-2024-1728

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
