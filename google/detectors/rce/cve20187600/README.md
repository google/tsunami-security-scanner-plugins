# Drupal RCE detector

This detector checks for [CVE-2018-7600](https://research.checkpoint.com/2018/uncovering-drupalgeddon-2) vulnerability in Drupal platforms. The vulnerability allows user to execute malicious code through the Drupal's FORM Api without any authentication.

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
