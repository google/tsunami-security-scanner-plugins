# Google Tsunami Plugins

![google-plugins-build](https://github.com/google/tsunami-security-scanner-plugins/workflows/google-plugins-build/badge.svg)

This directory contains all Tsunami plugins published by Google.

## Currently released plugins

### Port Scanner

*   [Nmap Port Scanner](https://github.com/google/tsunami-security-scanner-plugins/tree/master/google/portscan/nmap)

### Detectors

*   [WordPress Exposed Installation Page Detector](https://github.com/google/tsunami-security-scanner-plugins/tree/master/google/detectors/exposedui/wordpress)
*   [Exposed Hadoop Yarn ResourceManager API Detector](https://github.com/google/tsunami-security-scanner-plugins/tree/master/google/detectors/exposedui/hadoop/yarn)
*   [Exposed Jupyter Notebook Detector](https://github.com/google/tsunami-security-scanner-plugins/tree/master/google/detectors/exposedui/jupyter)
*   [Exposed Jenkins UI Detector](https://github.com/google/tsunami-security-scanner-plugins/tree/master/google/detectors/exposedui/jenkins)
*   [Ncrack Weak Credential Detector](https://github.com/google/tsunami-security-scanner-plugins/tree/master/google/detectors/credentials/ncrack)
*   [Apache Struts RCE (CVE-2017-5638)](https://github.com/google/tsunami-security-scanner-plugins/tree/master/google/detectors/rce/CVE-2017-5638)

## Build all plugins

Use the following command to build all Google released plugins:

```shell
./build_all.sh
```

All generated `jar` files are copied into `build/plugins` folder.
