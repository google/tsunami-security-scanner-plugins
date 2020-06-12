# Ncrack Weak Credential Detector

This `VulnDetector` is a thin wrapper around [ncrack](https://nmap.org/ncrack/),
which performs the required weak crednetials detection capability for Tsunami.

NOTE: this plugin doesn't ship a ncrack binary with it. Please install ncrack
from your package repository before using this plugin. Minimal required version
for ncrack is 0.7.

Checkout ncrack's project [homepage](https://nmap.org/ncrack) for detailed
information about the tool, use cases, license and restrictions.

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
