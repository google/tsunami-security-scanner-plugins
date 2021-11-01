# Apache Airflow Authentication Bypass on 'varimport' (CVE-2021-38540) Detector

The variable import endpoint was not protected by authentication in Airflow >=2.0.0, <2.1.3.
This allowed unauthenticated users to hit that endpoint to add/modify Airflow variables used
in DAGs, potentially resulting in a denial of service, information disclosure or remote code
execution. This issue affects Apache Airflow >=2.0.0, <2.1.3.

* [CVE-2021-38540](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-38540)


## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
