# Plugins for Tsunami Security Scanner

This project aims to provide a central repository for many useful Tsunami
Security Scanner plugins.

## Contributing

Read how to [contribute to Tsunami](docs/contributing.md).


## Currently released Tsunami plugins

### Detectors
#### AI Relevant OSS
* [Pytorch Serve Expose API Detector](https://github.com/google/tsunami-security-scanner-plugins/tree/master/google/detectors/exposedui/pytorch_serve)
* [Ray CVE-2023-48022 Detector](https://github.com/google/tsunami-security-scanner-plugins/tree/master/google/detectors/rce/ai/cve202348022)
* [Ray CVE-2023-6019 Detector](https://github.com/google/tsunami-security-scanner-plugins/tree/master/google/detectors/rce/ai/cve20236019)
* [H2O CVE-2023-6018 Detector](https://github.com/google/tsunami-security-scanner-plugins/tree/master/google/detectors/rce/ai/cve20236018)
* [MLflow CVE-2023-6977 & CVE-2023-1177 & CVE-2023-2780 Detector](https://github.com/google/tsunami-security-scanner-plugins/tree/master/community/detectors/mlflow_cve_2023_6977)
* [MLflow CVE-2023-6014 Detector](https://github.com/google/tsunami-security-scanner-plugins/tree/master/community/detectors/mlflow_cve_2023_6014)
* [MLflow Weak Credential Detector](https://github.com/google/tsunami-security-scanner-plugins/blob/master/google/detectors/credentials/generic_weak_credential_detector/src/main/java/com/google/tsunami/plugins/detectors/credentials/genericweakcredentialdetector/testers/mlflow/MlFlowCredentialTester.java)
* [Argo Workflow Exposed API Detector](https://github.com/google/tsunami-security-scanner-plugins/blob/master/google/detectors/exposedui/argoworkflow/)
* [MinIO Sensitive Info Disclosure Detector](https://github.com/google/tsunami-security-scanner-plugins/blob/master/community/detectors/minio_cve_2023_28432/)
* [Gradio CVE-2023-51449 Detector](https://github.com/google/tsunami-security-scanner-plugins/tree/master/community/detectors/gradio_cve_2023_51449)
* [Apache Spark CVE-2022-33891 Detector](https://github.com/google/tsunami-security-scanner-plugins/tree/master/community/detectors/apache_spark_cve_2022_33891)
* [Apache Spark Expose UI Detector](https://github.com/google/tsunami-security-scanner-plugins/tree/master/community/detectors/apache_spark_exposed_webui)
* [Apache Spark Exposed API Detector](https://github.com/google/tsunami-security-scanner-plugins/tree/master/community/detectors/rce/apache_spark_exposed_api)
* [Apache Airflow CVE-2020-17526 Auth Bypass RCE](https://github.com/google/tsunami-security-scanner-plugins/tree/master/community/detectors/apache_airflow_cve_2020_17526)
* [Triton Inference Server RCE](https://github.com/google/tsunami-security-scanner-plugins/tree/master/community/detectors/triton_inference_server_model_overwrite)
* [Intel Neural Compressor CVE-2024-22476 RCE Detector](https://github.com/google/tsunami-security-scanner-plugins/tree/master/community/detectors/intel_neural_compressor_cve_2024_22476)
* [ZenML Weak Credential Detector](https://github.com/google/tsunami-security-scanner-plugins/blob/master/google/detectors/credentials/generic_weak_credential_detector/src/main/java/com/google/tsunami/plugins/detectors/credentials/genericweakcredentialdetector/testers/zenml/ZenMlCredentialTester.java)
* [Argo CD Exposed UI](https://github.com/google/tsunami-security-scanner-plugins/tree/master/community/detectors/argocd_exposed_ui)
* [Airflow Exposed UI](https://github.com/google/tsunami-security-scanner-plugins/tree/master/community/detectors/apache_airflow_exposed_ui)

## Source Code Headers

Every file containing source code must include copyright and license
information. This includes any JS/CSS files that you might be serving out to
browsers. (This is to help well-intentioned people avoid accidental copying that
doesn't comply with the license.)

Apache header:

```
Copyright 2020 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

## Disclaimer

Tsunami Security Scanner and its plugins are not officially supported Google
products.
