# TorchServe Management API Detection Plugin
## Overview
This plugin detects and assesses the security risks of TorchServe Management API instances. Inspired by the ShellTorch vulnerability chain (disclosed by [Oligo Security](https://www.oligo.security/blog/shelltorch-torchserve-ssrf-vulnerability-cve-2023-43654)), it addresses the critical risks associated with insecure configurations of TorchServe, a widely used open-source application for serving PyTorch models in production.

## Background
TorchServe, before version 0.8.2, bound to `0.0.0.0` by default, potentially exposing its Management API to the internet. Since PyTorch models allow arbitrary code execution, unrestricted model addition poses significant risks including data leakage and user privacy breaches.

The original ShellTorch attack exploited [CVE-2022-1471](https://nvd.nist.gov/vuln/detail/CVE-2022-1471), a vulnerability fixed in TorchServe 0.8.2. However, the risk of executing arbitrary code in models remains in the latest version (0.9.0).

To mitigate these risks, TorchServe introduced the allow_urls feature, limiting model downloads to specified sources. However, a typical `allow_urls` configuration often includes entire services like GCP and AWS, which can be insecure. It's important to configure `allow_urls` carefully to avoid such vulnerabilities.

## Plugin Description
This plugin detects exposed TorchServe Management API instances, assessing the remote code execution (RCE) risk. It supports multiple detection modes:

### Static Mode
**Description:** Manually host a model file on a web server. Most reliable, particularly effective against lenient `allow_urls` configurations.
**Use case:** Ideal when `allow_urls` includes cloud services, posing a security risk.

```
--torchserve-management-api-mode=static --torchserve-management-api-model-static-url=https://s3.amazonaws.com/model.mar
```

### Local Mode
**Description:** Serve the model via an embedded web server. Quicker setup, but may fail against restrictive `allow_urls`.
**Use case:** Best for environments where `allow_urls` is not a limiting factor.

```
--torchserve-management-api-mode=local --torchserve-management-api-local-bind-host=tsunami --torchserve-management-api-local-bind-port=1234 --torchserve-management-api-local-accessible-url=http://mydomain.com/
```

### SSRF Mode
**Description:** Uses Tsunami's callback server as the model source. Indirect verification of RCE risk.
**Use case:** Selected when direct model serving isn't feasible or as an additional verification layer.

```
--torchserve-management-api-mode=ssrf
```

### Basic Mode
**Description:** Default mode that relies solely on Management API fingerprinting.
**Use case:** Automatically selected when callback server isn't available, useful as a preliminary check.

```
--torchserve-management-api-mode=basic
```

## Testing
Utilize the following testbed for assessing plugin functionality: [TorchServe Security Testbed](https://github.com/google/security-testbeds/tree/main/torchserve).
