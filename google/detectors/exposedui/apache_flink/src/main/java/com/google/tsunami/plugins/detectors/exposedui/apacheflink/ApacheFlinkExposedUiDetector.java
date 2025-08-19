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
package com.google.tsunami.plugins.detectors.exposedui.apacheflink;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.tsunami.common.net.http.HttpRequest.get;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpResponse;
import com.google.tsunami.common.time.UtcClock;
import com.google.tsunami.plugin.PluginType;
import com.google.tsunami.plugin.VulnDetector;
import com.google.tsunami.plugin.annotations.ForWebService;
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

/** A {@link VulnDetector} that detects unauthenticated Apache Flink. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "ApacheFlinkExposedUiDetector",
    version = "0.1",
    description =
        "This detector checks whether an unauthenticated Apache Flink UI instance is exposed to"
            + " anonymous users from the job submission, /#/submit, endpoint. If exposed, any user"
            + " can submit arbitrary jobs, which could result in remote code execution (RCE)",
    author = "Tsunami Team (tsunami-dev@google.com)",
    bootstrapModule = ApacheFlinkExposedUiDetectorBootstrapModule.class)
@ForWebService
public final class ApacheFlinkExposedUiDetector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  @VisibleForTesting
  static final String FINDING_RECOMMENDATION_TEXT =
      "Apache Flink Web UI does not support access control out of the box. Even if the feature to"
          + " upload jobs in the Apached Flink Web UI is disabled, the session cluster could still"
          + " accept job submission requests via REST calls. Per Apache Flink documentation, we"
          + " recommend adding authentication using a REST proxy. See"
          + " https://nightlies.apache.org/flink/flink-docs-master/docs/deployment/security/security-ssl/#external--rest-connectivity"
          + " and https://github.com/ing-bank/flink-deployer#authentication.";

  private final Clock utcClock;
  private final HttpClient httpClient;

  @Inject
  ApacheFlinkExposedUiDetector(@UtcClock Clock utcClock, HttpClient httpClient) {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient).modify().setFollowRedirects(false).build();
  }

  @Override
  public ImmutableList<Vulnerability> getAdvisories() {
    return ImmutableList.of(
        Vulnerability.newBuilder()
            .setMainId(
                VulnerabilityId.newBuilder()
                    .setPublisher("GOOGLE")
                    .setValue("APACHE_FLINK_EXPOSED_UI"))
            .setSeverity(Severity.CRITICAL)
            .setTitle("Apache Flink Exposed Ui")
            .setDescription("Apache Flink is not password or token protected")
            .setRecommendation(FINDING_RECOMMENDATION_TEXT)
            .build());
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("ApacheFlinkExposedUiDetector starts detecting.");

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
    String targetUri = NetworkServiceUtils.buildWebApplicationRootUrl(networkService) + "#/submit";
    try {
      HttpResponse response =
          httpClient.send(get(targetUri).withEmptyHeaders().build(), networkService);
      return response.status().isSuccess()
          && response
              .bodyString()
              .map(body -> body.contains("Apache Flink Web") && bodyContainsFlinkSubmit(body))
              // orElse fix operand types error as bodyString() type is Optional<String>
              .orElse(false);
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Unable to query '%s'.", targetUri);
      return false;
    }
  }

  private static boolean bodyContainsFlinkSubmit(String responseBody) {
    // An unauthenticated Apache Flink UI instance will display a flink-submit custom element
    // enabling anonymous users to submit malicious codes from the /#/submit endpoint.
    Elements flinkSubmit = Jsoup.parse(responseBody).select("flink-submit");
    if (flinkSubmit.isEmpty()) {
      logger.atInfo().log("Apache Flink UI does not allow creating new jobs as anonymous user.");
      return false;
    } else {
      logger.atInfo().log(
          "Apache Flink UI allows creating new jobs as anonymous user, enabling"
              + " remote code execution!");
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
        .setVulnerability(this.getAdvisories().get(0))
        .build();
  }
}
