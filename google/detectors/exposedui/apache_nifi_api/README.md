# Apache NiFi API Exposed UI Detector

This detector checks whether an unauthenticated Apache NiFi API is exposed.
Having it exposed puts the hosting VM at risk of RCE.

More details about the exploit can be found at
https://github.com/imjdl/Apache-NiFi-Api-RCE.

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
