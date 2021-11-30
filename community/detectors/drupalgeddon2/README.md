# Drupal RCE detector named Drupalgeddon2 

This detector checks if Drupal web application is vulnerable to CVE-2018-7600
(SA-CORE-2018-002) (named Drupalgeddon2), which allows remote code execution because of an issue
affecting multiple subsystems with default or common module configurations.
See https://www.drupal.org/sa-core-2018-002,
https://groups.drupal.org/security/faq-2018-002 for a details.

Credits to:
Hans Topo & g0tmi1k
https://github.com/dreadlocked/Drupalgeddon2

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```
