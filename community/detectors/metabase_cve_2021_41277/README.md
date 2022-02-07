# MetaBase CVE-2021-41277 Local File Inclusion Detector

This detector checks for MetaBase Local File Inclusion Vulnerability of CVE-2021-41277.Metabase is
an open source data analytics platform. In affected versions a security issue has been discovered
with the custom GeoJSON map (`admin->settings->maps->custom maps->add a map`) support and potential
local file inclusion (including environment variables). URLs were not validated prior to being
loaded. This issue is fixed in a new maintenance release (0.40.5 and 1.40.5), and any subsequent
release after that.

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
