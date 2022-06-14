# Jira Authentication Bypass Vulnerability Detector,Using insights prior to 8.10.0 and WBSGantt
plugin versions prior to 9.14.4.1 can cause a remote code execution hazard.

Jira Service Management Server and Data Center vulnerable to an authentication bypass in its web
authentication framework, Jira Seraph.
A remote, unauthenticated attacker could exploit this by requesting a specially crafted URL to bypass
authentication and authorization requirements in WebWork actions using an affected configuration.

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
