# PHP CVE-2012-1823 Detector

This plugin for Tsunami detects a remote code execution (RCE) vulnerability in
PHP that manifests when a query string is misinterpreted as command line
parameters to the CGI binary.

More information on the vulnerability:

* [CVE-2012-1823](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-1823)
* https://www.php.net/manual/en/security.cgi-bin.attacks.php
* https://blog.sucuri.net/2012/05/php-cgi-vulnerability-exploited-in-the-wild.html

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
