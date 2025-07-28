# PHP-CGI CVE-2024-4577 RCE Detector

This plugin detects CVE-2024-4577, a PHP RCE affecting deployments of PHP that
use Apache with CGI enabled and that run on Windows. An example of a vulnerable
environment is XAMPP, a popular platform for PHP development.

## Details

When using Apache and PHP-CGI on Windows, if the system is set up to use certain
code pages (such as the Japanese locale), Windows may use "Best-Fit" behavior to
replace characters in the command line given to Win32 API functions. The CGI
module of PHP may misinterpret those characters as PHP options, which may allow
a malicious user to pass options to the PHP binary being run, allowing to
achieve RCE.

**Affected PHP Versions** :-----:| PHP 8.3 < 8.3.8 PHP 8.2 < 8.2.20 PHP 8.1 <
8.1.29

## References

*   https://nvd.nist.gov/vuln/detail/cve-2024-4577
*   https://labs.watchtowr.com/no-way-php-strikes-again-cve-2024-4577/
*   https://github.com/watchtowrlabs/CVE-2024-4577

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
