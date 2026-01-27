# Alibaba Fastjson Insecure Deserialization RCE (CVE-2025-70974)

## Description

Fastjson before 1.2.48 contains an insecure deserialization vulnerability, which allows JNDI injection and Remote Code Execution.

## Affected Versions

-   < 1.2.48

## References

-   [Vulhub](https://github.com/vulhub/vulhub/tree/master/fastjson/1.2.47-rce)
-   [NIST](https://nvd.nist.gov/vuln/detail/CVE-2025-70974)

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

The Tsunami identifiable jar file is located at `build/libs` directory.
