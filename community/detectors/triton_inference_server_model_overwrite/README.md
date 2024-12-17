# Triton Inference Server Rce Detector

This detector checks triton inference server RCE with explicit model-control
option enabled. All versions of triton inference server with the
`--model-control explicit` option and at least one loaded model can be
overwritten by a malicious model and lead to RCE. As a recommendation don't use
`--model-control explicit` option with public access.

Ref:

-   https://protectai.com/threat-research/triton-inference-server-arbitrary-file-overwrite

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
