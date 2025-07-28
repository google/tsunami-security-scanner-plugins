# Doyensec Tsunami Plugins

![doyensec-plugins-build](https://github.com/google/tsunami-security-scanner-plugins/workflows/doyensec-plugins-build/badge.svg)

This directory contains all Tsunami plugins published by
[Doyensec](https://doyensec.com/).

## Currently released plugins

### Detectors

*   [RCE in Kubernetes Cluster with Open Access](https://github.com/google/tsunami-security-scanner-plugins/tree/master/doyensec/detectors/kubernetes_rce_via_open_access)
*   [RCE via Exposed Selenium Servers](https://github.com/google/tsunami-security-scanner-plugins/tree/master/doyensec/detectors/selenium_grid_rce_via_exposed_server)
*   [CVE-2022-26148 Grafana api_jsonrpc.php Zabbix Credential Disclosure](https://github.com/google/tsunami-security-scanner-plugins/tree/master/doyensec/detectors/grafana_zabbix_credential_disclosure)

## Build all plugins

Use the following command to build all Doyensec released plugins:

```
./build_all.sh
```

All generated `jar` files are copied into `build/plugins` folder.
