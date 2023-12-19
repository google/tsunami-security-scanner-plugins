/*
 * Copyright 2023 Google LLC
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
package com.google.tsunami.plugins.detectors.exposedui.drupalinstall;

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

/** A {@link VulnDetector} that detects an exposed and vulnerable Drupal installation. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "DrupalExposedInstallationDetector",
    version = "0.1",
    description = "This detector checks whether a Drupal installation is exposed and vulnerable",
    author = "Tsunami Team (tsunami-dev@google.com)",
    bootstrapModule = DrupalExposedInstallationDetectorBootstrapModule.class)
public final class DrupalExposedInstallationDetector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private final Clock utcClock;
  private final HttpClient httpClient;

  @Inject
  DrupalExposedInstallationDetector(@UtcClock Clock utcClock, HttpClient httpClient) {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient);
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("Starting DrupalExposedInstallationDetector.");

    DetectionReportList detectionReports =
        DetectionReportList.newBuilder()
            .addAllDetectionReports(
                matchedServices.stream()
                    .filter(NetworkServiceUtils::isWebService)
                    .filter(this::isServiceVulnerable)
                    .map(networkService -> buildDetectionReport(targetInfo, networkService))
                    .collect(toImmutableList()))
            .build();

    logger.atInfo().log("DrupalExposedInstallationDetector finished.");
    return detectionReports;
  }

  private boolean isServiceVulnerable(NetworkService networkService) {
    String targetUri =
        NetworkServiceUtils.buildWebApplicationRootUrl(networkService)
            + "/install.php?langcode=en&profile=standard&continue=1&locale=en";
    try {
      // This is a blocking call.
      HttpResponse response = httpClient.send(get(targetUri).withEmptyHeaders().build());
      return response.status().isSuccess()
          && response.bodyString().map(this::isInstallationVulnerable).orElse(false);
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Unable to query '%s'.", targetUri);
      return false;
    }
  }

  /*
   * The installation is only vulnerable if all preconditions for the installation are
   * met (e.g. the right file permissions are set). If the preconditions are met, the
   * requested link will trigger the installation process to proceed to the database
   * set up. If the preconditions are not met, the requested URL will display an error
   * message instead of proceeding to the database set up step.
   */
  private boolean isInstallationVulnerable(String body) {
    // We remove whitespaces here, because different drupal version behave differently with
    // regards to them. Older versions do not contain
    String bodyWithoutWhitespace = body.replaceAll("\\s", "");

    return isDrupalService(bodyWithoutWhitespace)
        && isInstallationForm(bodyWithoutWhitespace)
        && isDbSetupOrAdminCreationStep(bodyWithoutWhitespace);
  }

  private boolean isDrupalService(String bodyWithoutWhitespace) {
    return bodyWithoutWhitespace.contains("<metaname=\"Generator\"content=\"Drupal")
        && bodyWithoutWhitespace.contains("/misc/drupal.js?");
  }

  private boolean isInstallationForm(String bodyWithoutWhitespace) {
    return bodyWithoutWhitespace.contains("method=\"post\"id=\"install-settings-form\"")
        || bodyWithoutWhitespace.contains("method=\"post\"id=\"install-configure-form\"");
  }

  private boolean isDbSetupOrAdminCreationStep(String bodyWithoutWhitespace) {
    return bodyWithoutWhitespace.contains("<liclass=\"active\">Setupdatabase")
        || bodyWithoutWhitespace.contains("<liclass=\"is-active\">Setupdatabase")
        || bodyWithoutWhitespace.contains("<liclass=\"active\">Configuresite")
        || bodyWithoutWhitespace.contains("<liclass=\"is-active\">Configuresite");
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
                        .setValue("DRUPAL_VULNERABLE_INSTALLATION_EXPOSED"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("Drupal unfinished installation is exposed")
                // TODO: b/315448255 - Determine CVSS score.
                .setDescription(
                    "The drupal installation file is exposed and unfinished. Someone could hijack"
                        + "the installation process and execute code on the target machine.")
                .setRecommendation(
                    "Ensure Drupal is not externally accessible (firewall) until the installation"
                        + " is complete. Complete the installation process and set a strong"
                        + " password for the initial admin account."))
        .build();
  }
}
