# Kubernetes Open Access Remote Code Execution

The plugin detects a Kubernetes service with anonymous access and attempts to
execute arbitrary code by creating a new pod if excessive permissions have been
added to the system:anonymous user.

## Details

A Kubernetes cluster could be configured to allow open access by creating a role
to allow anonymous users (system:anonymous) to perform any action in a cluster
with:

`kubectl create clusterrolebinding cluster-system-anonymous
--clusterrole=cluster-admin --user=system:anonymous`

The plugin creates a pod using the API endpoint without authentication:

`/api/v1/namespaces/default/pods`

It brings up a pod with a container command: `curl` which sends a request to the
callback server to confirm RCE.

The plugin subsequently cleans up the created container with DELETE request to
the endpoint:

`/api/v1/namespaces/default/pods/tsunami-rce-pod API`

## References

[Demystifying RBAC in kubernetes](https://www.cncf.io/blog/2018/08/01/demystifying-rbac-in-kubernetes/)
[Kubernetes Anonymous access risks](https://github.com/kubernetes-sigs/apiserver-builder-alpha/issues/225#issuecomment-501444546)
[Tsunami Callback Server](https://github.com/google/tsunami-security-scanner-callback-server)

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
