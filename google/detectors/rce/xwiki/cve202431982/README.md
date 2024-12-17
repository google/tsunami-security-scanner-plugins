# CVE-2024-31982 RCE for xwiki

This detector checks whether an xwiki instance is vulnerable to RCE-2024-31982
which allows unauthenticated code execution.

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
