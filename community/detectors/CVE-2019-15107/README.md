# CVE-2019-15107 VulnDetector

This detector checks for Webmin password_change.cgi Command Injection (CVE-2019-15107 ).
The vulnerability was secretly planted by an unknown hacker who successfully managed to inject a BACKDOOR at some point
in its build infrastructure that surprisingly persisted into various releases of Webmin (1.882 through 1.921) and
eventually remained hidden for over a year.
Developers confirmed that the official Webmin downloads were replaced by the backdoored packages only on the project's
SourceForge repository, and not on the Webmin's Github repositories.

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.

## References
 - https://www.pentest.com.tr/exploits/DEFCON-Webmin-1920-Unauthenticated-Remote-Command-Execution.html
 - https://github.com/advisories/GHSA-69hp-hrv4-rxrr