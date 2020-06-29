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

## Exported config values

Config properties prefix: `plugins.google.detectors.credentials.ncrack`.

Config values:

*   `ncrack_binary_path`: specifies the location of the `ncrack` binary path.

Example YAML config:

```yaml
plugins:
  google:
    detectors:
      credentials:
        ncrack:
          ncrack_binary_path: "/usr/local/bin/ncrack"
```
