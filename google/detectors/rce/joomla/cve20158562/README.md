# Joomla RCE CVE-2015-8562 Detector

This plugin checks if a Joomla web application is vulnerable to CVE-2015-8562.
The vulnerability leads to arbitrary PHP execution by injecting and
deserializing a PHP object via the User-Agent or the X-Forwarded-For header.

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
