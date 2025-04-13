# Exposed Hadoop Yarn ResourceManager API Detector

Hadoop Yarn ResourceManager controls the computation and storage resources of a
Hadoop cluster. This detector checks whether the ResouceManager API is exposed
without authentication, which allows any remote user to create and execute
arbitrary applications on the host.

Hadoop version affected for sure is 2.8.1, probably earlier versions as well.

See more details here:

https://github.com/Al1ex/Hadoop-Yarn-ResourceManager-RCE

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
