# MLFlow Path Traversal Vulnerability Detector

A path traversal vulnerability exists in `mlflow/mlflow` version < `2.12.1`, allowing attackers to access arbitrary files on the server. By crafting a series of HTTP POST requests with specially crafted `artifact_location` and `source` parameters, using a local URI with `#` instead of `?`, an attacker can traverse the server's directory structure. The issue occurs due to insufficient validation of user-supplied input in the server's handlers.

Affected versions < 2.12.1

Patched versions 2.12.1 and above

References:

- [Huntr Security Report](https://huntr.com/bounties/52a3855d-93ff-4460-ac24-9c7e4334198d)
- [CVE-2024-1483](https://www.cve.org/CVERecord?id=CVE-2024-1483)

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.


Limitation: 
- This method relies on reaching /etc/passwd to confirm traversal; if unreachable, it may cause false negatives. 
- Accessing /etc/passwd can expose sensitive system data, so use with caution and only in controlled environments.