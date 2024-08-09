# CVE-2024-23897 Detector

Description: Jenkins uses the args4j library to parse command arguments and
options on the Jenkins controller when processing CLI commands. This command
parser has a feature that replaces an @ character followed by a file path in an
argument with the file’s contents (expandAtFiles). This feature is enabled by
default and Jenkins 2.441 and earlier, LTS 2.426.2 and earlier does not disable
it. This allows attackers to read arbitrary files on the Jenkins controller file
system using the default character encoding of the Jenkins controller process.

-   https://nvd.nist.gov/vuln/detail/CVE-2024-23897
-   https://www.jenkins.io/security/advisory/2024-01-24/

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
