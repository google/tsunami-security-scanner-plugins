# MLflow CVE-2023-6014 Auth Bypass Vulnerability Detector

This detector checks for MLflow CVE-2023-6014 Auth Bypass vulnerability.

MLflow instances below version 2.8.0 which use MLFlow UI or MLFlow Server have
an authentication bypass vulnerability. Normally MLFlow requires authentication
for user creation operations who are served under /mlflow/users/create API.
However, due to a coding mistake, prepending /api/2.0/ to those routes will
allow access to an unauthenticated remote attacker in the vulnerable versions,
namely /api/2.0/mlflow/users/create. Therefore, unauthenticated attackers can
create users by using this endpoint and reach the functionalities of MLflow.

-   https://huntr.com/bounties/3e64df69-ddc2-463e-9809-d07c24dc1de4
-   https://nvd.nist.gov/vuln/detail/CVE-2023-6014

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
