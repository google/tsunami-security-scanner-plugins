# Arbitrary File Read in ComfyUI Manager via filename

## Description

In ComfyUI it's possible to leak the content of an arbitrary file on the system. This is due to a missing check that fails to validate that the user supplied filename does not escape the intended output directory.

 By leveraging the `file:` protocol an attacker can read a file on the system. After that, he can supply the webroot path, hence the file will be publicly readable. 

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

The Tsunami identifiable jar file is located at `build/libs` directory.
