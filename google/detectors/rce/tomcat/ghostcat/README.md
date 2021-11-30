# Ghostcat (CVE-2020-1938) Detector

This detector checks for exposed AJP connectors that can be exploited by
Ghostcat (CVE-2020-1938), which allows file read/inclusion and can lead to RCE
when in the right setting. See https://www.tenable.com/blog/cve-2020-1938-ghostcat-apache-tomcat-ajp-file-readinclusion-vulnerability-cnvd-2020-10487
for more details.

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
