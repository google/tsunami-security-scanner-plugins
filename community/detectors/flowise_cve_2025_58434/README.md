# Flowise CVE-2025-58434 Detector

This Tsunami plugin detects Flowise authentication bypass vulnerability (CVE-2025-58434). Flowise is a drag &
drop UI tool for building LLM applications. The vulnerability allows credential retrieval via 
the forgot-password endpoint by knowing the email address of a user.

## Description

The detector performs the following checks: - Fingerprints Flowise instances by checking the main page title 
and tests the forgot-password endpoint for authentication bypass

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
