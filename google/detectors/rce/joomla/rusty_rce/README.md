# Joomla Rusty RCE Detector

This plugin checks if a Joomla web application is vulnerable to Rusty RCE (no
CVE available).
The vulnerability leads to arbitrary PHP execution by injecting and
deserializing a PHP object via the user login form.
Affecting Joomla CMS from the release 3.0.0 to the 3.4.6
(releases from 2012 to December 2015).

Credits to:
Alessandro Groppo
https://blog.hacktivesecurity.com/index.php?controller=post&action=view&id_post=41

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
