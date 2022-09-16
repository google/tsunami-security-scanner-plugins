/*
 * Copyright 2022 Google LLC
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

package com.google.tsunami.plugins.detectors.exposedui.apachenifi.apivuln;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.tsunami.common.net.http.HttpRequest.get;

import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
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

/** A {@link VulnDetector} that detects whether Apache NiFi API allows authentication bypass. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "ApacheNiFiApiExposedUiDetector",
    version = "0.1",
    // Detailed description about what this plugin does.
    description =
        "This detector checks whether an unauthenticated Apache NiFi API is exposed. Having it"
            + " exposed puts the hosting VM at risk of RCE.",
    author = "Pankhuri Saxena (pankhurisaxena@google.com)",
    bootstrapModule = ApacheNiFiApiExposedUiDetectorBootstrapModule.class)
public final class ApacheNiFiApiExposedUiDetector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  private static final String VULNERABLE_ENDPOINT = "nifi-api/access/config";

  private final Clock utcClock;
  private final HttpClient httpClient;

  @Inject
  ApacheNiFiApiExposedUiDetector(@UtcClock Clock utcClock, HttpClient httpClient) {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient).modify().setFollowRedirects(true).build();
  }
  /** Method for detecting the vulnerability and returning the corresponding detection report */
  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("Starting detection for Apache NiFi API Exposed UI.");

    // create and return the detection report by checking whether service is vulnerable
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
   * Method for checking whether the service is vulnerable. Sends a get request for extracting the
   * config data.
   */
  private boolean isServiceVulnerable(NetworkService networkService) {
    String targetUri = NetworkServiceUtils.buildWebApplicationRootUrl(networkService);
    targetUri = targetUri + VULNERABLE_ENDPOINT;
    HttpResponse response;

    // plain GET request to get config data
    logger.atInfo().log("Accessing config data on target '%s'.", targetUri);
    try {
      response = httpClient.send(get(targetUri).withEmptyHeaders().build(), networkService);
      if (!response.status().isSuccess()) {
        // log a warning if the get request wasn't successful and return false
        logger.atWarning().log("Response status code: %s.", response.status().code());
        return false;
      }
      // extract supportsLogin contents
      return doesConfigSupportsLoginFalse(response);
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Unable to query '%s'.", targetUri);
      return false;
    }
  }

  /** Extract the supportsLogin parameter from the response and checks whether it is false. */
  private static boolean doesConfigSupportsLoginFalse(HttpResponse response) {
    String json = response.bodyBytes().get().toString();
    int index = json.indexOf("supportsLogin");
    return json.substring(index + 16, index + 21).equals("false");
  }

  /** Method for building the detection report. */
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
                        .setValue("APACHE_NIFI_API_EXPOSED_UI"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("Apache NiFi API Exposed UI")
                .setDescription("Apache NiFi API is not password or token protected.")
                .setRecommendation(
                    "Do not expose Apache NiFi API externally. Add authentication or bind it to"
                        + " local network."))
        .build();
  }
}
