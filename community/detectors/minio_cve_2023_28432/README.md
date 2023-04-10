# MinIO Information Disclosure in Cluster Environment VulnDetector


This detector checks for [CVE-2023-28432](https://github.com/minio/minio/security/advisories/GHSA-6xvq-wj2x-3h3q), a Information Disclosure Vulnerability in MinIO Cluster deployments.
It confirms that the leaked credentials are actually working by performing an authentication request.

The plugin also checks for cluster instances were no key/secret is set and the [default credentials](https://min.io/docs/minio/linux/administration/identity-access-management/minio-user-management.html) (minioadmin:minioadmin) are used.

The following cases are detected:

1. Fixed instance with default credentials
2. Vulnerable instance with default credentials (no environment variable set)
3. Vulnerable instance with (deprecated) MINIO_ACCESS_KEY environment variable
4. Vulnerable instance with MINIO_ROOT_PASSWORD environment variable

Docker compose files for each case can be found [here](https://github.com/h0ng10/CVE-2023-28432_docker).

For authentication, this plugin uses code from the [MinIO Java SDK](https://github.com/minio/minio-java), which is licensed under Apache 2.0 license.
The code has been minimized and adjusted to work with Tsunamis own httpclient instead of okhttp.


## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
