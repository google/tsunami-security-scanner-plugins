# D-Tale CVE-2025-0655 Detector

This detector checks for D-Tale Remote Code Execution (CVE-2025-0655). This vulnerability 
allows an attacker to modify the global application settings, enabling the enable_custom_filters
feature and thereby gaining access to the /test-filter endpoint for RCE. Exploiting this issue can 
lead to unauthorized command execution, server compromise, data theft, and other severe consequences.

-   https://huntr.com/bounties/f63af7bd-5438-4b36-a39b-4c90466cff13
-   https://vulmon.com/vulnerabilitydetails?qid=CVE-2025-0655&sortby=bydate&scoretype=cvssv2

## Build jar file for this plugin

Using `gradlew`:

```sh
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
