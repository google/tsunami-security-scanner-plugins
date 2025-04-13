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
package com.google.tsunami.plugins.detectors.exposedui.phpunit;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;

import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.protobuf.ByteString;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpRequest;
import com.google.tsunami.common.net.http.HttpResponse;
import com.google.tsunami.common.time.UtcClock;
import com.google.tsunami.plugin.PluginType;
import com.google.tsunami.plugin.VulnDetector;
import com.google.tsunami.plugin.annotations.PluginInfo;
import com.google.tsunami.plugins.detectors.exposedui.phpunit.Annotations.RunMode;
import com.google.tsunami.plugins.detectors.exposedui.phpunit.Annotations.ScriptPaths;
import com.google.tsunami.plugins.detectors.exposedui.phpunit.PHPUnitExposedEvalStdinDetectorBootstrapModule.Mode;
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
import java.io.IOException;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import javax.inject.Inject;

/** A {@link VulnDetector} that detects exposed eval-stdin.php script. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "PHPUnitExposedEvalStdinDetector",
    version = "0.1",
    description =
        "This detector checks for CVE-2017-9841 RCE vulnerability in phpunit. For vulnerable"
            + " versions of phpunit, its eval-stdin.php script allows RCE via a POST request "
            + "payload.",
    author = "Tsunami Team (tsunami-dev@google.com)",
    bootstrapModule = PHPUnitExposedEvalStdinDetectorBootstrapModule.class)
public final class PHPUnitExposedEvalStdinDetector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private static final ByteString PHP_PAYLOAD =
      ByteString.copyFromUtf8("<?php echo(base64_decode('dHN1bmFtaS1waHB1bml0'));");
  private static final String EVAL_STDIN_SCRIPT_PATH =
      "vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php";
  private final Clock utcClock;
  private final HttpClient httpClient;
  private final Mode runMode;
  private final ImmutableList<String> scriptPaths;

  @Inject
  PHPUnitExposedEvalStdinDetector(
      @UtcClock Clock utcClock,
      HttpClient httpClient,
      @RunMode Mode runMode,
      @ScriptPaths ImmutableList<String> scriptPaths) {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient);
    this.runMode = checkNotNull(runMode);
    this.scriptPaths = checkNotNull(scriptPaths);
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("Starting exposed ui detection for eval-stdin.php script.");

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
    String rootUrl = NetworkServiceUtils.buildWebApplicationRootUrl(networkService);

    List<String> targetPaths = new ArrayList<>();
    if (runMode == Mode.DEFAULT) {
      targetPaths.add(EVAL_STDIN_SCRIPT_PATH);
    } else {
      targetPaths.addAll(scriptPaths);
    }

    for (String path : targetPaths) {
      String uri = rootUrl + path;
      try {
        logger.atInfo().log("Trying to inject php payload to target '%s'", uri);
        // This is a blocking call.
        HttpResponse response =
            httpClient.send(
                HttpRequest.post(uri).setRequestBody(PHP_PAYLOAD).withEmptyHeaders().build(),
                networkService);
        if (response.status().isSuccess()
            && response.bodyString().isPresent()
            && response.bodyString().get().contains("tsunami-phpunit")) {
          return true;
        }
      } catch (IOException e) {
        logger.atWarning().withCause(e).log("Unable to query '%s'.", uri);
      }
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
                .setMainId(
                    VulnerabilityId.newBuilder()
                        .setPublisher("GOOGLE")
                        .setValue("EXPOSED_PHPUNIT_EVAL_STDIN"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("CVE-2017-9841: Exposed Vulnerable eval-stdin.php in PHPUnit")
                .setDescription(
                    "CVE-2017-9841: For vulnerable versions of PHPUnit, its eval-stdin.php script"
                        + " allows RCE via a POST request payload.")
                .setRecommendation("Remove the PHPUnit module or upgrade to the latest version.")
                .addAdditionalDetails(
                    AdditionalDetail.newBuilder()
                        .setTextData(
                            TextData.newBuilder()
                                .setText("Vulnerable endpoint: " + EVAL_STDIN_SCRIPT_PATH))))
        .build();
  }
}
