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
package com.google.tsunami.plugins.detectors.exposedui.wordpress;

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
import org.jsoup.Jsoup;
import org.jsoup.select.Elements;

/** A {@link VulnDetector} that detects unfinished WordPress install. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "WordPressInstallPageDetector",
    version = "0.1",
    description =
        "This detector checks whether a WordPress install is unfinished. An unfinished WordPress"
            + " installation exposes the /wp-admin/install.php page, which allows attacker to set"
            + " the admin password and possibly compromise the system.",
    author = "Tsunami Team (tsunami-dev@google.com)",
    bootstrapModule = WordPressInstallPageDetectorBootstrapModule.class)
public final class WordPressInstallPageDetector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private final Clock utcClock;
  private final HttpClient httpClient;

  @Inject
  WordPressInstallPageDetector(@UtcClock Clock utcClock, HttpClient httpClient) {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient);
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("Starting unfinished install page detection for WordPress.");
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
        "WordPressInstallPageDetector finished, detected '%d' vulns.",
        detectionReports.getDetectionReportsCount());
    return detectionReports;
  }

  private boolean isServiceVulnerable(NetworkService networkService) {
    String targetUri =
        NetworkServiceUtils.buildWebApplicationRootUrl(networkService)
            + "wp-admin/install.php?step=1";
    try {
      // This is a blocking call.
      HttpResponse response =
          httpClient.send(get(targetUri).withEmptyHeaders().build(), networkService);
      return response.status().isSuccess()
          // TODO(b/147455416): checking WordPress string is not needed once we have plugin
          // matching logic.
          && response
              .bodyString()
              .map(body -> body.contains("WordPress") && responseHasSetupForm(body))
              .orElse(false);
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Unable to query '%s'.", targetUri);
      return false;
    }
  }

  private static boolean responseHasSetupForm(String responseBody) {
    Elements installationForm = Jsoup.parse(responseBody).select("form#setup");
    if (installationForm.isEmpty()) {
      logger.atInfo().log("WordPress has already been installed.");
      return false;
    } else {
      logger.atInfo().log("Found unfinished WordPress installation!");
      return true;
    }
  }

  private DetectionReport buildDetectionReport(
      TargetInfo scannedTarget, NetworkService vulnerableNetworkService) {
    return DetectionReport.newBuilder()
        .setTargetInfo(scannedTarget)
        .setNetworkService(vulnerableNetworkService)
        .setDetectionTimestamp(Timestamps.fromMillis(Instant.now(utcClock).toEpochMilli()))
        .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
        .setVulnerability(
            Vulnerability.newBuilder()
                .setMainId(
                    VulnerabilityId.newBuilder()
                        .setPublisher("GOOGLE")
                        .setValue("UNFINISHED_WORD_PRESS_INSTALLATION"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("Unfinished WordPress Installation")
                // TODO(b/147455416): determine CVSS score.
                .setDescription(
                    "An unfinished WordPress installation exposes the /wp-admin/install.php page,"
                        + " which allows attacker to set the admin password and possibly"
                        + " compromise the system."))
        .build();
  }
}
