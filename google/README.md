# Google Tsunami Plugins

![google-plugins-build](https://github.com/google/tsunami-security-scanner-plugins/workflows/google-plugins-build/badge.svg)

This directory contains all Tsunami plugins published by Google.

## Currently released plugins

### Port Scanner

*   [Nmap Port Scanner](https://github.com/google/tsunami-security-scanner-plugins/tree/master/google/portscan/nmap)

### Fingerprinter

*   [Web Service Fingerprinter](https://github.com/google/tsunami-security-scanner-plugins/tree/master/google/fingerprinters/web)

### Detectors

#### Authentication
*   [MantisBT Authentication Bypass Detector (CVE-2017-7615)](https://github.com/google/tsunami-security-scanner-plugins/tree/master/google/detectors/credentials/cve20177615)
*   [Ncrack Weak Credential Detector](https://github.com/google/tsunami-security-scanner-plugins/tree/master/google/detectors/credentials/ncrack)

#### Exposed Sensitive UI/API
*   [Exposed Elasticsearch API Detector](https://github.com/google/tsunami-security-scanner-plugins/tree/master/google/detectors/exposedui/elasticsearch)
*   [Exposed Hadoop Yarn ResourceManager API Detector](https://github.com/google/tsunami-security-scanner-plugins/tree/master/google/detectors/exposedui/hadoop/yarn)
*   [Exposed Jenkins UI Detector](https://github.com/google/tsunami-security-scanner-plugins/tree/master/google/detectors/exposedui/jenkins)
*   [Exposed Jupyter Notebook Detector](https://github.com/google/tsunami-security-scanner-plugins/tree/master/google/detectors/exposedui/jupyter)
*   [Exposed Kubernetes APIDetector](https://github.com/google/tsunami-security-scanner-plugins/tree/master/google/detectors/exposedui/kubernetes)
*   [Exposed PHPUnit Vulnerable eval-stdin.php Detector](https://github.com/google/tsunami-security-scanner-plugins/tree/master/google/detectors/exposedui/phpunit)
*   [Exposed Spring Boot Actuator Endpoint Detector](https://github.com/google/tsunami-security-scanner-plugins/tree/master/google/detectors/exposedui/spring)
*   [Exposed WordPress Installation Page Detector](https://github.com/google/tsunami-security-scanner-plugins/tree/master/google/detectors/exposedui/wordpress)

#### Remote Code Execution (RCE)
*   [PHP RCE (CVE-2012-1823) Detector](https://github.com/google/tsunami-security-scanner-plugins/tree/master/google/detectors/rce/cve20121823)
*   [Apache Struts Command Injection via Content-Type Header (CVE-2017-5638) Detector](https://github.com/google/tsunami-security-scanner-plugins/tree/master/google/detectors/rce/cve20175638)
*   [Apache Struts Command Injection via Unsafe Deserialization (CVE-2017-9805) Detector](https://github.com/google/tsunami-security-scanner-plugins/tree/master/google/detectors/rce/cve20179805)
*   [Apache Struts Command Injection via Namespace (CVE-2018-11776) Detector](https://github.com/google/tsunami-security-scanner-plugins/tree/master/google/detectors/rce/cve201811776)
*   [Jenkins CLI Deserialization RCE (CVE-2017-1000353) Detector](https://github.com/google/tsunami-security-scanner-plugins/tree/master/google/detectors/rce/cve20171000353)
*   [Java Unprotected JMX Server Detector](https://github.com/google/tsunami-security-scanner-plugins/tree/master/google/detectors/rce/java_jmx)
*   [Joomla RCE (CVE-2015-8562) Detector](https://github.com/google/tsunami-security-scanner-plugins/tree/master/google/detectors/rce/joomla/cve20158562)
*   [Joomla Rusty RCE Detector](https://github.com/google/tsunami-security-scanner-plugins/tree/master/google/detectors/rce/joomla/rusty_rce)
*   [Liferay Portal RCE (CVE-2020-7961) Detector](https://github.com/google/tsunami-security-scanner-plugins/tree/master/google/detectors/rce/liferay_portal/cve20207961)
*   [Apache Solr VelocityResponseWriter RCE (CVE-2019-17558) Detector](https://github.com/google/tsunami-security-scanner-plugins/tree/master/google/detectors/rce/solr_cve201917558)
*   [Tomcat Ghostcat (CVE-2020-1938) Detector](https://github.com/google/tsunami-security-scanner-plugins/tree/master/google/detectors/rce/tomcat/ghostcat)
*   [vBulletin Pre-Auth RCE (CVE-2019-16759) Detector](https://github.com/google/tsunami-security-scanner-plugins/tree/master/google/detectors/rce/vbulletin/cve201916759)

## Planned Detectors

*  Exposed unauthenticated [Adminer](https://www.adminer.org/) server.
*  Exposed [Hashicorp Consul](https://www.consul.io/) API with enabled script checks.
*  Exposed [Docker](https://www.docker.com/) daemon API.
*  Exposed unauthenticated [Drupal](https://www.drupal.org/) installation page.
*  Exposed unauthenticated [GoCD](https://www.gocd.org/) server.
*  Exposed unauthenticated [Kubernetes](https://kubernetes.io/) master server.
*  Exposed unauthenticated [phpMyAdmin](https://www.phpmyadmin.net/) server.

## Build all plugins

Use the following command to build all Google released plugins:

```shell
./build_all.sh
```

All generated `jar` files are copied into `build/plugins` folder.
