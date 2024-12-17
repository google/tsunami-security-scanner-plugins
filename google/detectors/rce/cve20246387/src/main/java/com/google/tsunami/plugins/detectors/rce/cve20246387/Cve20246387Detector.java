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
package com.google.tsunami.plugins.detectors.rce.cve20246387;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;

import com.google.common.annotations.VisibleForTesting;
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
import javax.inject.Inject;

/** A {@link VulnDetector} that detects CVE-2024-6387. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "Cve20246387Detector",
    version = "0.1",
    description = "Detects CVE-2024-6387.",
    author = "Tsunami Team (tsunami-dev@google.com)",
    bootstrapModule = Cve20246387DetectorBootstrapModule.class)
public final class Cve20246387Detector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  private static final ImmutableList<String> VULNERABLE_BANNER_VERSIONS_SUFFIX =
      ImmutableList.of(
          // Ubuntu
          "8.8p1 Ubuntu-1",
          "8.9p1 Ubuntu-3",
          "8.9p1 Ubuntu-3ubuntu0.1",
          "8.9p1 Ubuntu-3ubuntu0.3",
          "8.9p1 Ubuntu-3ubuntu0.4",
          "8.9p1 Ubuntu-3ubuntu0.5",
          "8.9p1 Ubuntu-3ubuntu0.6",
          "8.9p1 Ubuntu-3ubuntu0.7",
          "8.9p1 Ubuntu-3ubuntu0.7+Fips1",
          "9.0p1 Ubuntu-1ubuntu7",
          "9.0p1 Ubuntu-1ubuntu7.1",
          "9.0p1 Ubuntu-1ubuntu8.4",
          "9.0p1 Ubuntu-1ubuntu8.7",
          "9.3p1 Ubuntu-1ubuntu3.2",
          "9.3p1 Ubuntu-1ubuntu3.3",
          "9.6p1 Ubuntu-3ubuntu13",
          // Debian
          "8.7p1 Debian-4",
          "9.0p1 Debian-1+b1",
          "9.2p1 Debian-2",
          "9.2p1 Debian-2+deb12u1",
          "9.2p1 Debian-2+deb12u2",
          "9.3p1 Debian-1",
          "9.4p1 Debian-1",
          "9.6p1 Debian-2",
          "9.6p1 Debian-3",
          "9.6p1 Debian-4",
          "9.7p1 Debian-4",
          "9.7p1 Debian-5",
          "9.7p1 Debian-6");

  @VisibleForTesting
  static final String TITLE =
      "CVE-2024-6387 Unauthenticated Remote Code Execution in OpenSSH Server";

  @VisibleForTesting
  static final String DESCRIPTION =
      "A signal handler race condition was found in OpenSSH's server (sshd), where a client does"
          + " not authenticate within LoginGraceTime seconds (120 by default, 600 in old OpenSSH"
          + " versions), then sshd's SIGALRM handler is called asynchronously. However, this signal"
          + " handler calls various functions that are not async-signal-safe, for example,"
          + " syslog().";

  @VisibleForTesting
  static final String RECOMMENDATION =
      "Upgrade OpenSSH to the latest version or restrict the access to the SSH server to trusted"
          + " peers. When upgrade is not available, you could set the `LoginGraceTime` parameter to"
          + " 0 in OpenSSH config file at `/etc/ssh/sshd_config` and restart the OpenSSH server.";

  private final Clock utcClock;

  @Inject
  Cve20246387Detector(@UtcClock Clock utcClock) {
    this.utcClock = checkNotNull(utcClock);
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("Scanning CVE-2024-6387 via banner comparison.");
    return DetectionReportList.newBuilder()
        .addAllDetectionReports(
            matchedServices.stream()
                .filter(this::hasOpenSshBanner)
                .filter(this::isServiceVulnerable)
                .map(networkService -> buildDetectionReport(targetInfo, networkService))
                .collect(toImmutableList()))
        .build();
  }

  private boolean hasOpenSshBanner(NetworkService networkService) {
    return networkService.getBannerCount() > 0
        && networkService.getBannerList().stream()
            .anyMatch(banner -> banner.contains("SSH-2.0-OpenSSH"));
  }

  private boolean isServiceVulnerable(NetworkService networkService) {
    return networkService.getBannerList().stream()
        .map(String::trim)
        .anyMatch(banner -> VULNERABLE_BANNER_VERSIONS_SUFFIX.stream().anyMatch(banner::endsWith));
  }

  private DetectionReport buildDetectionReport(
      TargetInfo targetInfo, NetworkService networkService) {
    ImmutableList<AdditionalDetail> additionalDetails =
        networkService.getBannerList().stream()
            .map(
                banner ->
                    AdditionalDetail.newBuilder()
                        .setTextData(TextData.newBuilder().setText(banner))
                        .build())
            .collect(toImmutableList());

    return DetectionReport.newBuilder()
        .setTargetInfo(targetInfo)
        .setNetworkService(networkService)
        .setDetectionTimestamp(Timestamps.fromMillis(utcClock.millis()))
        .setDetectionStatus(DetectionStatus.VULNERABILITY_PRESENT)
        .setVulnerability(
            Vulnerability.newBuilder()
                .setMainId(
                    VulnerabilityId.newBuilder().setPublisher("GOOGLE").setValue("CVE-2024-6387"))
                .addRelatedId(
                    VulnerabilityId.newBuilder().setPublisher("CVE").setValue("CVE-2024-6387"))
                .setSeverity(Severity.CRITICAL)
                .setTitle(TITLE)
                .setDescription(DESCRIPTION)
                .setRecommendation(RECOMMENDATION)
                .addAllAdditionalDetails(additionalDetails))
        .build();
  }
}
