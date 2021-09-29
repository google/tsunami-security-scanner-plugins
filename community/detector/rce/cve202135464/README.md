# ForgeRock AM/OpenAM CVE-2021-35464 Detector

This plugin detects an pre-auth remote code execution vulnerability in OpenAM that
can be used for executing remote arbitrary code.

More information on the vulnerability:

* [CVE-2021-35464](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-35464)
* https://nvd.nist.gov/vuln/detail/CVE-2021-35464

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
