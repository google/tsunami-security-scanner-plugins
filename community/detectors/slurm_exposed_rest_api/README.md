# Slurm Exposed REST API

This detector checks for exposed slurm REST API daemon by running an arbitrary command. The Slurm Rest API requires
authentication by default. However, a common configuration involves using a reverse proxy that (theoretically) should
authenticate the user with some other methods and, if successful, authenticates towards the Slurm Rest API using a
hardcoded JWT token that is injected into the forwarded request's headers.

Reference:

- https://slurm.schedmd.com/rest.html#auth_proxy

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
