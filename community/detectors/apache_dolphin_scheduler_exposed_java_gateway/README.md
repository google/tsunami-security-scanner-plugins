# Apache DolphinScheduler Exposed Java Gateway Detector

This Tsunami plugin identifies Apache DolphinScheduler instances with an exposed Java Gateway using default credentials. Apache DolphinScheduler is an open-source distributed workflow scheduler designed to manage complex data and task workflows.

## Vulnerability

The platform uses different credentials for its UI and Java Gateway API (based on [Py4j](https://github.com/py4j/py4j)). The Java Gateway API comes with a default authentication token when deployed via the official Docker image (`apache/dolphinscheduler-standalone-server`).

According to the [configuration guide](https://dolphinscheduler.apache.org/python/main/config.html), when DolphinScheduler is deployed with the Docker image, it uses the default auth token:

```
auth_token: jwUDzpLsNKEFER4*a8gruBH_GsAurNxU7A@Xc
```

When the Java Gateway is exposed with default credentials, anyone can authenticate and perform tasks (e.g., Shell, Python), which could lead to remote code execution (RCE) on the DolphinScheduler worker nodes.

## Build

Using `gradlew`:

```shell
./gradlew jar
```

The Tsunami-identifiable jar file is located in the `build/libs` directory.

## References

- [Apache DolphinScheduler](https://dolphinscheduler.apache.org/)
- [DolphinScheduler Python SDK Configuration](https://dolphinscheduler.apache.org/python/main/config.html)
- [Py4j Protocol](https://www.py4j.org/)
- [Docker Deployment Guide](https://dolphinscheduler.apache.org/docs/latest/user_doc/guide/installation/docker.html)
