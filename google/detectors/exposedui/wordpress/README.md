# WordPress Exposed Installation Page Detector

This detector checks whether a WordPress install is unfinished. An unfinished
WordPress installation exposes the /wp-admin/install.php page, which allows
attacker to set the admin password and possibly compromise the system.

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
