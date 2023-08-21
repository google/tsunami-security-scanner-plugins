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
package com.google.tsunami.plugins.papercut;

import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.*;
import com.google.tsunami.common.time.UtcClock;
import com.google.tsunami.plugin.PluginType;
import com.google.tsunami.plugin.VulnDetector;
import com.google.tsunami.plugin.annotations.PluginInfo;
import com.google.tsunami.proto.*;

import javax.inject.Inject;
import java.io.IOException;
import java.time.Clock;
import java.time.Instant;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;

@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "PapercutNGMRVulnDetectorWithPayload",
    version = "1.0",
    description = "Detects papercut versions that are vulnerable to authentication bypass and RCE.",
    author = "Isaac_GC (isaac@nu-that.us)",
    // How should Tsunami scanner bootstrap your plugin.
    bootstrapModule = PapercutNGMFVulnDetectorBootstrapModule.class)
// Optionally, each VulnDetector can be annotated by service filtering annotations. For example, if
// the VulnDetector should only be executed when the scan target is running Jenkins, then add the
// following @ForSoftware annotation.
// @ForSoftware(name = "Jenkins")
public final class PapercutNGMFVulnDetector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private final Clock utcClock;
  private final HttpClient httpClient;

  @Inject
  PapercutNGMFVulnDetector(
      @UtcClock Clock utcClock, HttpClient httpClient) {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient).modify().setFollowRedirects(false).build();
  }

  // This is the main entry point of your VulnDetector. Both parameters will be populated by the
  // scanner. targetInfo contains the general information about the scan target. matchedServices
  // parameter contains all the network services that matches the service filtering annotations
  // mentioned earlier. If no filtering annotations added, then matchedServices parameter contains
  // all exposed network services on the scan target.
  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("CVE-2023-27350 (PaperCut NG/MF) starts detecting.");

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
    String rootUri = NetworkServiceUtils.buildWebApplicationRootUrl(networkService);
    String targetUri = rootUri + "/app?service=page/SetupCompleted";
    boolean isVulnerable = false;

    HttpHeaders headers = HttpHeaders.builder().addHeader("Origin", rootUri).build();

    HttpRequest req = HttpRequest.post(targetUri).setHeaders(headers).build();


    try {
      HttpResponse res = httpClient.send(req, networkService);
      String content = res.bodyString().orElse(null);

      Matcher matches;
      if (content != null) {
        matches = Pattern
                .compile("Configuration Wizard : Setup Complete")
                .matcher(content);

        // if a response code 302 (HttpStatus.FOUND) and/or the title isn't match, then it isn't a vulnerable version
        if (res.status() == HttpStatus.OK && matches.find()) {
          isVulnerable = true;
        }
      }

      return isVulnerable;
    } catch (IOException e) {
      return false;
    }
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
                        .setPublisher("TSUNAMI_COMMUNITY")
                        .setValue("CVE_2023_27350"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("Papercut NG/MF Authentication Bypass and RCE")
                .setDescription(
                        "This vulnerability allows remote attackers to bypass authentication" +
                                " on affected installations of PaperCut NG/MF." +
                                " Authentication is not required to exploit this vulnerability." +
                                " The specific flaw exists within the SetupCompleted class and the" +
                                " issue results from improper access control." +
                                " An attacker can leverage this vulnerability to bypass authentication" +
                                " and execute arbitrary code in the context of SYSTEM (Windows) " +
                                "or Root/Papercut User (Linux)."
                )
                .setRecommendation("Update to versions that are at least 20.1.7, 21.2.11, 22.0.9, or any later version.")
                )
        .build();
  }
}
