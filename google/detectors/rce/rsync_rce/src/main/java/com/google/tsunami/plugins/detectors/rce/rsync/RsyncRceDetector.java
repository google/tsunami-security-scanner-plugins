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
package com.google.tsunami.plugins.detectors.rce.rsync;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;

import com.google.common.base.Ascii;
import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.time.UtcClock;
import com.google.tsunami.plugin.PluginType;
import com.google.tsunami.plugin.VulnDetector;
import com.google.tsunami.plugin.annotations.ForServiceName;
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
import java.util.regex.Pattern;
import javax.inject.Inject;

/** Detects embargoed rsync RCE reported in b/377501700. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "RsyncRceDetector",
    version = "0.1",
    description = "Detects rsync RCE CVE-2024-12084.",
    author = "Tsunami Team (tsunami-dev@google.com)",
    bootstrapModule = RsyncRceDetectorBootstrapModule.class)
@ForServiceName({"rsync"})
public final class RsyncRceDetector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  // WARNING: This is false-positive prone until the information of the CVE is
  // fully disclosed. This relies on a rsync commit at
  // https://github.com/RsyncProject/rsync/commit/536ae3f4efbcd95bee1f9794bbeceb50ba5f0dba
  // to be ported by OS vendors from upstream.
  private static final Pattern VULNERABLE_BANNER_PATTERN =
      Pattern.compile("@RSYNCD:\\s31.0(\\s\\w+)+");

  static final String VULN_DESCRIPTION =
      "A heap-buffer-overflow vulnerability in the Rsync daemon results in improper handling of"
          + " attacker-controlled checksum lengths (s2length). When the MAX_DIGEST_LEN exceeds the"
          + " fixed SUM_LENGTH (16 bytes), an attacker can write out-of-bounds in the sum2 buffer.";

  static final String VULN_RECOMMENDATION = "Please upgrade rsync version to 3.4.0 or later.";

  private final Clock utcClock;

  @Inject
  RsyncRceDetector(@UtcClock Clock utcClock) {
    this.utcClock = checkNotNull(utcClock);
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("RsyncRceDetector started.");
    var rsyncBanner = new Banner();
    return DetectionReportList.newBuilder()
        .addAllDetectionReports(
            matchedServices.stream()
                .filter(this::isRsyncService)
                .filter(networkService -> isServiceVulnerable(networkService, rsyncBanner))
                .map(
                    networkService -> buildDetectionReport(targetInfo, networkService, rsyncBanner))
                .collect(toImmutableList()))
        .build();
  }

  @Override
  public ImmutableList<Vulnerability> getAdvisories() {
    return ImmutableList.of(getAdvisory(AdditionalDetail.getDefaultInstance()));
  }

  Vulnerability getAdvisory(AdditionalDetail details) {
    return Vulnerability.newBuilder()
        .setMainId(VulnerabilityId.newBuilder().setPublisher("GOOGLE").setValue("RSYNC_SERVER_RCE"))
        .setSeverity(Severity.CRITICAL)
        .addRelatedId(VulnerabilityId.newBuilder().setPublisher("CVE").setValue("CVE-2024-12084"))
        .setTitle(
            "CVE-2024-12084 Heap Buffer Overflow leading to Remote Code Execution in Rsync Server")
        .setDescription(VULN_DESCRIPTION)
        .setRecommendation(VULN_RECOMMENDATION)
        .addAdditionalDetails(details)
        .build();
  }

  private boolean isRsyncService(NetworkService networkService) {
    return Ascii.equalsIgnoreCase(networkService.getServiceName(), "rsync");
  }

  private boolean isServiceVulnerable(NetworkService networkService, Banner rsyncBanner) {
    var banners = networkService.getBannerList();
    if (banners.isEmpty()) {
      logger.atInfo().log("rsync server returned no banner.");
      return false;
    }
    rsyncBanner.banner = banners.get(0);
    return VULNERABLE_BANNER_PATTERN.matcher(rsyncBanner.banner).matches();
  }

  private DetectionReport buildDetectionReport(
      TargetInfo targetInfo, NetworkService vulnerableNetworkService, Banner rsyncBanner) {
    return DetectionReport.newBuilder()
        .setTargetInfo(targetInfo)
        .setNetworkService(vulnerableNetworkService)
        .setDetectionTimestamp(Timestamps.fromMillis(utcClock.instant().toEpochMilli()))
        .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
        .setVulnerability(
            getAdvisory(
                AdditionalDetail.newBuilder()
                    .setDescription("Rsync banner")
                    .setTextData(TextData.newBuilder().setText(rsyncBanner.banner))
                    .build()))
        .build();
  }

  private static class Banner {
    String banner;
  }
}
