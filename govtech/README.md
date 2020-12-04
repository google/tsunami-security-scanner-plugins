# Google Tsunami Plugins

![govtech-plugins-build](https://github.com/google/tsunami-security-scanner-plugins/workflows/govtech-plugins-build/badge.svg)

This directory contains all Tsunami plugins published by GovTech.

## Currently released plugins

### Detectors

*   [CVE-2020-3452](https://github.com/google/tsunami-security-scanner-plugins/tree/master/govtech/detectors/cves/cve_2020_3452)

## Build all plugins

Use the following command to build all GovTech released plugins:

```
./build_all.sh
```

All generated `jar` files are copied into `build/plugins` folder.
