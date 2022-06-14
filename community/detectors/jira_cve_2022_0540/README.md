# Jira Authentication Bypass Vulnerability Detector for Insights & WBSGantt Plugins

Jira Service Management Server and Data Center vulnerable to an authentication bypass in its web
authentication framework, Jira Seraph.
A remote, unauthenticated attacker could exploit this by requesting a specially crafted URL to bypass
authentication and authorization requirements in WebWork actions using an affected configuration.
This detector specifically detects auth bypass in the affected Jira versions with either
Insights (prior to 8.10.0) or WBSGantt (prior to 9.14.4.1) plugin installed.

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
