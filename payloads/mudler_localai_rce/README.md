# How to compile a Python Code for Mudler LocalAI?

First of all, build the Docker file:

```
docker build -t build-env . -f Dockerfile
```

Use the newly created Docker to build the binary:

```
docker run -it --rm build-env bash
(docker) /opt $ python3 app_bin_compile.py
```

Then copy the binary out:

```
docker cp nameOfTheContainer:/opt/app.bin .
```

And exit the container.
