# Apache Sparks exposed Web UI

This detector checks for an exposed Apache Spark Web UI.

An Apache Spark Web Ui which is exposed to an attacker might disclose sensitive
information to them. An attacker can retrieve information such as the configured
workers and master node within the Apache Sparks environment. Furthermore, an
attacker gains access to the output logs of run tasks. This might disclose
sensitive information if a task is logging sensitive information during its
execution.

The Web UI is exposed on the root path of the Apache Sparks instance. An
exemplary URI might look like the following: `http://<apache_spark_host>:8080/`

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
