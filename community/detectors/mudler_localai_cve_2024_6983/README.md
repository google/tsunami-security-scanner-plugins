# Mudler LocalAI RCE CVE-2024-6983 Detector

Mudler LocalAI versions before 2.19.4 are vulnerable to remote code execution. The vulnerability 
arises because the localai backend receives inputs not only from the configuration file but also 
from other inputs, allowing an attacker to upload a binary file and execute malicious code. This 
can lead to the attacker gaining full control over the system.


-   https://huntr.com/bounties/f91fb287-412e-4c89-87df-9e4b6e609647
-   https://sightline.protectai.com/vulnerabilities/b182990f-02ea-49d0-9fad-61030cbe6460/assess

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
