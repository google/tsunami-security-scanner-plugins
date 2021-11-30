# Example VulnDetector

This is an example implementation of a `VulnDetector` plugin for Tsunami that
calls external command line tools. This is useful when your `VulnDetector`
relies on other binary/scripts for the scanning job. For example you can write
real detection logic in python or go and call the binary within a Tsunami
`VulnDetector`.

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
