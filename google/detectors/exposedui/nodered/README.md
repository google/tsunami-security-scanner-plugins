# NodeRED unprotected instance

This detector checks whether a NodeRED instance is available without
authentication (which allows very easy RCE).

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
