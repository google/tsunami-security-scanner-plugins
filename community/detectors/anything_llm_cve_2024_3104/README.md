# Anything-llm CVE-2024-3104 Detector

A remote code execution vulnerability exists in mintplex-labs/anything-llm due
to improper handling of environment variables. Attackers can exploit this
vulnerability by injecting arbitrary environment variables via the POST
/api/system/update-env endpoint, which allows for the execution of arbitrary
code on the host running anything-llm. The vulnerability is present in the
latest version of anything-llm, with the latest commit identified as
fde905aac1812b84066ff72e5f2f90b56d4c3a59. This issue has been fixed in version
1.0.0. Successful exploitation could lead to code execution on the host,
enabling attackers to read and modify data accessible to the user running the
service, potentially leading to a denial of service.

-   https://huntr.com/bounties/4f2fcb45-5828-4bec-985a-9d3a0ee00462
-   https://vulners.com/nvd/NVD:CVE-2024-3104

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
