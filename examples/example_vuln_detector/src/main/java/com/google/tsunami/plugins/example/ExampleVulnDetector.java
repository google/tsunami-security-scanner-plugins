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
package com.google.tsunami.plugins.example;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;

import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.time.UtcClock;
import com.google.tsunami.plugin.PluginType;
import com.google.tsunami.plugin.VulnDetector;
import com.google.tsunami.plugin.annotations.PluginInfo;
import com.google.tsunami.proto.AdditionalDetail;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.TextData;
import com.google.tsunami.proto.Vulnerability;
import com.google.tsunami.proto.VulnerabilityId;
import java.time.Clock;
import java.time.Instant;
import javax.inject.Inject;

/** An example VulnDetector plugin. */
// PluginInfo tells Tsunami scanning engine basic information about your plugin.
@PluginInfo(
    // Which type of plugin this is.
    type = PluginType.VULN_DETECTION,
    // A human readable name of your plugin.
    name = "ExampleVulnDetector",
    // Current version of your plugin.
    version = "0.1",
    // Detailed description about what this plugin does.
    description = "This is an example plugin.",
    // Author of this plugin.
    author = "Alice (alice@company.com)",
    // How should Tsunami scanner bootstrap your plugin.
    bootstrapModule = ExampleVulnDetectorBootstrapModule.class)
// Optionally, each VulnDetector can be annotated by service filtering annotations. For example, if
// the VulnDetector should only be executed when the scan target is running Jenkins, then add the
// following @ForSoftware annotation.
// @ForSoftware(name = "Jenkins")
public final class ExampleVulnDetector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private final Clock utcClock;

  // Tsunami scanner relies heavily on Guice framework. So all the utility dependencies of your
  // plugin must be injected through the constructor of the detector. Here the UtcClock is provided
  // by the scanner.
  @Inject
  ExampleVulnDetector(@UtcClock Clock utcClock) {
    this.utcClock = checkNotNull(utcClock);
  }

  // This is the main entry point of your VulnDetector. Both parameters will be populated by the
  // scanner. targetInfo contains the general information about the scan target. matchedServices
  // parameter contains all the network services that matches the service filtering annotations
  // mentioned earlier. If no filtering annotations added, then matchedServices parameter contains
  // all exposed network services on the scan target.
  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("ExampleVulnDetector starts detecting.");

    // An example implementation for a VulnDetector.
    return DetectionReportList.newBuilder()
        .addAllDetectionReports(
            matchedServices.stream()
                // Check individual NetworkService whether it is vulnerable.
                .filter(unused -> isServiceVulnerable())
                // Build DetectionReport message for vulnerable services.
                .map(networkService -> buildDetectionReport(targetInfo, networkService))
                .collect(toImmutableList()))
        .build();
  }

  // Checks whether a given network service is vulnerable. Real detection logic implemented here.
  private boolean isServiceVulnerable() {
    return true;
  }

  // This builds the DetectionReport message for a specific vulnerable network service.
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
                        .setPublisher("vulnerability_id_publisher")
                        .setValue("VULNERABILITY_ID"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("Vulnerability Title")
                .setDescription("Detailed description of the vulnerability")
                .addAdditionalDetails(
                    AdditionalDetail.newBuilder()
                        .setTextData(
                            TextData.newBuilder().setText("Some additional technical details."))))
        .build();
  }
}
