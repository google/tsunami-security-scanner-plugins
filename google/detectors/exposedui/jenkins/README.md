# Exposed Jenkins UI Detector

This detector checks unauthenticated Jenkins instance by sending a probe ping to
/view/all/newJob endpoint as an anonymous user. An authenticated Jenkins
instance will show the createItem form, which allows the anonymous user to
create arbitrary jobs that could lead to RCE.

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
