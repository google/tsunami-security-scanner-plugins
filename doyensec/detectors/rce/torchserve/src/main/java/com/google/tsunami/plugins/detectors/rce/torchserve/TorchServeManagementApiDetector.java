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
package com.google.tsunami.plugins.detectors.rce.torchserve;

import static com.google.common.base.Preconditions.checkNotNull;

import java.time.Clock;
import java.time.Instant;

import javax.inject.Inject;

import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.time.UtcClock;
import com.google.tsunami.plugin.PluginType;
import com.google.tsunami.plugin.VulnDetector;
import com.google.tsunami.plugin.annotations.ForWebService;
import com.google.tsunami.plugin.annotations.PluginInfo;
import com.google.tsunami.proto.*;
import com.google.tsunami.proto.NetworkService;

@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "TorchServeManagementApiDetector",
    version = "0.1",
    description = "Detects publicly available TorchServe management API with a path to RCE.",
    author = "Andrew Konstantinov (andrew@doyensec.com)",
    bootstrapModule = TorchServeManagementApiDetectorBootstrapModule.class)
@ForWebService
public final class TorchServeManagementApiDetector implements VulnDetector {
  private final TorchServeExploiter torchServeExploiter;
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  public static final String REPORT_PUBLISHER = "DOYENSEC";
  public static final String REPORT_ID = "TORCHSERVE_MANAGEMENT_API_RCE";
  public static final String REPORT_TITLE = "TorchServe Management API Remote Code Execution";
  public static final String REPORT_RECOMMENDATION =
    "It is strongly recommended to restrict access to the TorchServe Management API, as " +
    "public exposure poses significant security risks. The API allows potentially " +
    "disruptive interactions with TorchServe, including modifying configurations, " +
    "deleting models, and altering resource allocation, which could lead to Denial of " +
    "Service (DoS) attacks. \n\n" +
    "Particular attention should be given to the possibility of unauthorized code " +
    "execution through model uploads. Users must ensure strict control over model " +
    "creation to prevent unauthorized or malicious use. Implementing the 'allowed_urls' " +
    "option in TorchServe's configuration is critical in this regard. This setting, " +
    "detailed at https://pytorch.org/serve/configuration.html#:~:text=allowed_urls, " +
    "limits the URLs from which models can be downloaded. \n\n" +
    "It is essential to configure 'allowed_urls' as a comma-separated list of " +
    "regular expressions that specifically allow only trusted sources. General " +
    "whitelisting of large domains (such as entire AWS S3 or GCP buckets) is not " +
    "secure. Care must be taken to ensure regex patterns are accurately defined " +
    "(e.g., using 'https://models\\.my-domain\\.com/*' instead of " +
    "'https://models.my-domain.com/*' to prevent unintended domain matches). \n\n" +
    "Finally, be aware that the Management API discloses the original URLs of " +
    "downloaded models. Attackers could exploit this information to identify " +
    "vulnerable download sources or to host malicious models on similarly-named " +
    "domains.";
  private final Clock utcClock;

  @Inject
  public TorchServeManagementApiDetector(TorchServeExploiter torchServeExploiter, @UtcClock Clock utcClock) {
    this.utcClock = checkNotNull(utcClock);
    this.torchServeExploiter = checkNotNull(torchServeExploiter);
  }

  /**
   * Detects vulnerabilities in the given target. Called by Tsunami that handles the port scanning
   * and service fingerprinting.
   *
   * @param targetInfo Information about the target system.
   * @param matchedServices List of matched network services.
   * @return A list of detection reports.
   */
  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    DetectionReportList.Builder reportListBuilder = DetectionReportList.newBuilder();

    for (NetworkService service : matchedServices) {
      try {
        TorchServeExploiter.Details details = torchServeExploiter.isServiceVulnerable(service);
        logger.atInfo().log("Checking service %s", service);
        if (details != null) {
          logger.atInfo().log("Found vulnerable service %s", service);
          DetectionReport report = buildDetectionReport(targetInfo, service, details);
          reportListBuilder.addDetectionReports(report);
        }
      } catch (Exception e) {
        logger.atWarning().withCause(e).log("Error processing service %s", service);
      }
    }
    return reportListBuilder.build();
  }

  /** Builds a vulnerability object. */
  private Vulnerability buildVulnerability(TorchServeExploiter.Details details) {
    VulnerabilityId vulnerabilityId =
        VulnerabilityId.newBuilder().setPublisher(REPORT_PUBLISHER).setValue(REPORT_ID).build();
    return Vulnerability.newBuilder()
        .setTitle(REPORT_TITLE)
        .setDescription(details.generateDescription())
        .setRecommendation(REPORT_RECOMMENDATION)
        .addAdditionalDetails(
            AdditionalDetail.newBuilder()
                .setDescription("Additional details")
                .setTextData(
                    TextData.newBuilder().setText(details.generateAdditionalDetails()).build())
                .build())
        .setSeverity(details.getSeverity())
        .setMainId(vulnerabilityId)
        .build();
  }

  /**
   * Builds a detection report for a given target and service.
   *
   * @param targetInfo Information about the target.
   * @param service The network service associated with the vulnerability.
   * @return The constructed detection report.
   */
  private DetectionReport buildDetectionReport(
      TargetInfo targetInfo, NetworkService service, TorchServeExploiter.Details details) {
    Vulnerability vulnerability = buildVulnerability(details);
    return buildDetectionReport(targetInfo, service, vulnerability, details.isVerified());
  }

  /**
   * Builds a detection report for a given target, service and vulnerability.
   *
   * @param targetInfo
   * @param service
   * @param vulnerability
   * @return The constructed detection report.
   */
  private DetectionReport buildDetectionReport(
      TargetInfo targetInfo,
      NetworkService service,
      Vulnerability vulnerability,
      boolean verified) {
    DetectionReport report =
        DetectionReport.newBuilder()
            .setTargetInfo(targetInfo)
            .setNetworkService(service)
            .setDetectionTimestamp(Timestamps.fromMillis(Instant.now(utcClock).toEpochMilli()))
            .setDetectionStatus(
                verified
                    ? DetectionStatus.VULNERABILITY_VERIFIED
                    : DetectionStatus.VULNERABILITY_PRESENT)
            .setVulnerability(vulnerability)
            .build();
    return report;
  }
}
