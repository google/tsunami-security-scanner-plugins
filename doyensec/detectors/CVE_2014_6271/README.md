# CVE-2014-6271 - ShellShock

This detector checks for
[CVE-2014-6271](https://nvd.nist.gov/vuln/detail/CVE-2014-6271) aka ShellShock.
It covers webserver that exposes cgi files processed with bash `<=4.3`. This
detector checks for the following list of default files on every service
identified as `WebService`:

-   `""`
-   `/cgi-bin/status`
-   `/cgi-bin/stats`
-   `/cgi-bin/test`
-   `/cgi-bin/status/status.cgi`
-   `/test.cgi`
-   `/debug.cgi`
-   `/cgi-bin/test-cgi`
-   `/cgi-bin/test.cgi`

This detector works with and without callback server, and uses a different
payload for each mode.

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
