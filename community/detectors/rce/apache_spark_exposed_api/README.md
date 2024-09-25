# Apache Sparks exposed API

This detector checks for exposed Apache Spark API servers.

This API server, which does not have authentication enabled, is exposed if an
Apache Sparks instance has the environment variable `spark.master.rest.enabled:
true` set upon startup.

An attacker can exploit this API to gain remote code execution by submitting a
malicious Apache Sparks task, which dynamically loads attacker-controlled code.

Exploit of this issue requires a POST request to the following URI:
`http://<apache_spark_host>:6066/v1/submissions/create`

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
