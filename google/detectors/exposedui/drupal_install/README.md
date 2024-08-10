# Drupal exploitable installation exposed

This detector checks whether a drupal exploitable installation file is exposed.
The installation UI is vulnerable if all the installation preconditions are met,
and the installation UI is accessible without authentication. In this case,
an attacker can trigger the installation by providing an attacker-controlled
database backend. Via a rouge database backend the attacker can inject code.

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
