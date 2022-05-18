# Jira Authentication Bypass Vulnerability Detector

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
