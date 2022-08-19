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
package com.google.tsunami.plugins.detectors.rce.cve20179805;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.common.net.HttpHeaders.CONTENT_TYPE;
import static com.google.tsunami.common.net.http.HttpRequest.get;
import static com.google.tsunami.common.net.http.HttpRequest.post;
import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.common.io.Resources;
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
import javax.inject.Inject;

/**
 * A {@link VulnDetector} that detects Apache Struts Command Injection via Unsafe Deserialization
 * (CVE-2017-9805). We test that the application is vulnerable to the RCE by creating and erasing a
 * file in the root directory and verifying that it can be accessed through HTTP requests. We also
 * check the contents of the file to avoid false positives from fake HTTP services that return 200
 * for any queried path. We should change this to use a back-connection instead once Tsunami has
 * support for that.
 */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "ApacheStrutsInsecureDeserializeDetector",
    version = "0.1",
    description =
        "Tsunami detector plugin for Apache Struts Command Injection via Unsafe Deserialization"
            + " (CVE-2017-9805).",
    author = "Tsunami Team (tsunami-dev@google.com)",
    bootstrapModule = ApacheStrutsInsecureDeserializeDetectorBootstrapModule.class)
public final class ApacheStrutsInsecureDeserializeDetector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  static final String RANDOM_FILENAME = "v896sWLe6WA2zF3qJea7.txt";
  static final String RANDOM_FILE_CONTENTS = "7Z8Y62lPYUxPfQxCZv4bOlqs3CNhoYEtSwyY16Av";
  private final Clock utcClock;
  private final HttpClient httpClient;
  private final String payloadFormatString;

  @Inject
  ApacheStrutsInsecureDeserializeDetector(@UtcClock Clock utcClock, HttpClient httpClient) {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient);
    String payloadFormatString = "";
    try {
      payloadFormatString =
          Resources.toString(
              Resources.getResource(this.getClass(), "payloadFormatString.xml"), UTF_8);
    } catch (IOException e) {
      logger.atSevere().withCause(e).log(
          "Should never happen. Couldn't load payload resource file");
    }
    this.payloadFormatString = payloadFormatString;
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log(
        "Starting Command Injection via Unsafe Deserialization (CVE-2017-9805) detection for"
            + " Apache Struts.");
    DetectionReportList detectionReports =
        DetectionReportList.newBuilder()
            .addAllDetectionReports(
                matchedServices.stream()
                    .filter(NetworkServiceUtils::isWebService)
                    .filter(this::isServiceVulnerable)
                    .map(networkService -> buildDetectionReport(targetInfo, networkService))
                    .collect(toImmutableList()))
            .build();

    logger.atInfo().log(
        "ApacheStrutsInsecureDeserializeDetector finished, detected '%d' vulns.",
        detectionReports.getDetectionReportsCount());
    return detectionReports;
  }

  private boolean isServiceVulnerable(NetworkService networkService) {
    String targetUri = NetworkServiceUtils.buildWebApplicationRootUrl(networkService);

    try {
      executeCommand(
          networkService,
          targetUri,
          String.format(
              "echo \"%s\" > $CATALINA_HOME/webapps/ROOT/%s",
              RANDOM_FILE_CONTENTS, RANDOM_FILENAME));
      boolean fileCreated =
          isFilePresent(networkService, targetUri, RANDOM_FILENAME, RANDOM_FILE_CONTENTS);

      // Clean up. We remove the file even if we were not able to query it since it's possible that
      // it still got created and we just didn't find the right webapp root path.
      executeCommand(
          networkService,
          targetUri,
          String.format("rm $CATALINA_HOME/webapps/ROOT/%s", RANDOM_FILENAME));
      boolean fileRemoved =
          !isFilePresent(networkService, targetUri, RANDOM_FILENAME, RANDOM_FILE_CONTENTS);

      return fileCreated && fileRemoved;
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Unable to query '%s'.", targetUri);
      return false;
    }
  }

  // Attempt to send an XML payload to the service that executes `command`.
  private void executeCommand(NetworkService networkService, String targetUri, String command)
      throws IOException {
    // This is a blocking call.
    String payload = String.format(payloadFormatString, command);
    HttpHeaders headers = HttpHeaders.builder().addHeader(CONTENT_TYPE, "application/xml").build();
    httpClient.send(
        post(targetUri)
            .setHeaders(headers)
            .setRequestBody(ByteString.copyFrom(payload, "UTF-8"))
            .build(),
        networkService);
  }

  private boolean isFilePresent(
      NetworkService networkService, String targetUri, String filename, String contents)
      throws IOException {
    HttpResponse response =
        httpClient.send(get(targetUri + filename).withEmptyHeaders().build(), networkService);
    return response.status() == HttpStatus.OK
        && response.bodyBytes().isPresent()
        && response.bodyBytes().get().toString("UTF-8").trim().equals(contents);
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
                    VulnerabilityId.newBuilder().setPublisher("GOOGLE").setValue("CVE_2017_9805"))
                .setSeverity(Severity.CRITICAL)
                .setTitle(
                    "Apache Struts Command Injection via Unsafe Deserialization (CVE-2017-9805)")
                .setDescription(
                    "The REST Plugin in Apache Struts 2.1.1 through 2.3.x before 2.3.34 and 2.5.x"
                        + " before 2.5.13 uses an XStreamHandler with an instance of XStream for"
                        + " deserialization without any type filtering, which can lead to Remote"
                        + " Code Execution when deserializing XML payloads.")
                .setRecommendation("Upgrade to Struts 2.5.13 or Struts 2.3.34."))
        .build();
  }
}
