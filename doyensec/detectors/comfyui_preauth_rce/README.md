# Pre-Auth Remote Code Execution in ComfyUI

## Description

In ComfyUI it's possible to clone repository. After the cloning process, certain
files on the repository are executed. There is a pitfall in the entire flow,
since the repository URL supplied by the user is checked with an allow list,
but another parameter is used in order to clone the repo. This can lead to
remote code execution.

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

The Tsunami identifiable jar file is located at `build/libs` directory.
