# Exposed Pytorch Serve Notebook Detector

This detector checks whether a Pytorch Serve API is exposed.
Pytorch Serve API allows a request to upload arbitrary models.
Having it exposed puts the hosting VM at risk of RCE.

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
