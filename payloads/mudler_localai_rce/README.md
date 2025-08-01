# How to compile a Python Code for Mudler LocalAI?

First of all, build the Docker file:

```
docker build -t build-env . -f Dockerfile
```

After that run its Docker container and attach a volume to it for obtaining the PyInstaller compiled binary (Here I attached /opt path of container to /container path of my host machine) :

```
docker run -it -v /container:/opt build-env
```

After that, you will be in a bash from the container. You can move the app_bin_compile.py file to the selected directory, and from the terminal, you can run the following command to get the app.bin file.

```
python3 /opt/app_bin_compile.py
```
