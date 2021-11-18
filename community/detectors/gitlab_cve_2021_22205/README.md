# CVE-2021-22205 VulnDetector

This detector checks for GitLab CE/EE Unauthenticated RCE using ExifTool and disclosure vulnerability (CVE-2021-29441).
An issue has been discovered(no authentication required) in GitLab CE/EE affecting all versions starting from 11.9. GitLab was not properly validating image files that were passed to a file parser which resulted in a remote command execution.
This issue is known to be exploited in the wild.

- https://security.humanativaspa.it/gitlab-ce-cve-2021-22205-in-the-wild/
- https://hackerone.com/reports/1154542
- https://nvd.nist.gov/vuln/detail/CVE-2021-22205


## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
