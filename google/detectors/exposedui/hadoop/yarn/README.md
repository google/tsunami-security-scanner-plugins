# Exposed Hadoop Yarn ResourceManager API Detector

Hadoop Yarn ResourceManager controls the computation and storage resources of a
Hadoop cluster. This detector checks whether the ResouceManager API is exposed
without authentication, which allows any remote user to create and execute
artibrary applications on the host.

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
