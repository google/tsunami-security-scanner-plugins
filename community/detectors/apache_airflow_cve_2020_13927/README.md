# CVE-2020-13927 VulnDetector

On Apache Airflow versions prior to 1.10.10, Airflow's Experimental API was to allow all API requests without authentication, but this poses security risks to users who miss this fact.

- https://nvd.nist.gov/vuln/detail/CVE-2020-13927
- https://packetstormsecurity.com/files/174764/Apache-Airflow-1.10.10-Remote-Code-Execution.html
- https://lists.apache.org/thread/mq1bpqf3ztg1nhyc5qbrjobfrzttwx1d


## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
