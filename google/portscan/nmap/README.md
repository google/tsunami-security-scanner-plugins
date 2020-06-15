# Nmap PortScanner

This `PortScanner` is a thin wrapper around [nmap](https://nmap.org), which
performs the required port scanning functionality for Tsunami.

NOTE: this plugin doesn't ship a nmap binary with it. Please install nmap from
your package repository before using this plugin.

Checkout nmap's project [homepage](https://nmap.org) for detailed information
about the tool, use cases, license and restrictions.

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.

## Exported config values

Config properties prefix: `plugins.google.port_scanner.nmap`.

Config values:

*   `port_targets`: specifies which ports the plugin should scan and overrides
    the default. Expected format is a comma separated list of individual ports
    and port ranges, e.g. `80,8080,15000-16000`.

Example YAML config:

```yaml
plugins:
  google:
    port_scanner:
      nmap:
        port_targets: "80,8080,15000-16000"
```
