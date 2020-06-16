# Exposed Jupyter Notebook Detector

This detector checks whether an unauthenticated Jupyter Notebook is exposed.
Jupyter allows by design to run arbitrary code on the host machine. Having it
exposed puts the hosting VM at risk of RCE.

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
