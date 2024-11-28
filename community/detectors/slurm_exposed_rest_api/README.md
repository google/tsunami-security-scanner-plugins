# Slurm Exposed REST API

his detector checks for an exposed Slurm REST API service by running an arbitrary command using the Tsunami Callback
Server.

The Slurm Rest API requires authentication by default. However, a common configuration involves using a reverse proxy
that (in correctly-configured environments) should authenticate the user first using some other methods and, if
successful, inject a JWT token into the request before forwarding it to the Slurm REST API service.

If the reverse proxy is misconfigured to simply forward the requests without any authentication steps, it will allow
anyone to use the API and therefore get RCE by submitting malicious jobs to the cluster.

- https://slurm.schedmd.com/rest.html#auth_proxy

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
