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
package com.google.tsunami.plugins.detectors.exposedui.jenkins;

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

/**
 * A {@link VulnDetector} that detects unauthenticated Jenkins.
 *
 * <p>This detector checks unauthenticated Jenkins instance by sending a probe ping to <code>
 * /view/all/newJob</code> endpoint as an anonymous user. An authenticated Jenkins instance will
 * direct this probe to <code>/login</code> page. An unauthenticated Jenkins instance will show the
 * <code>createItem</code> form, which allows the anonymous user to create arbitrary jobs which
 * leads to remote code executions.
 */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "JenkinsExposedUiDetector",
    version = "0.1",
    description =
        "This detector checks unauthenticated Jenkins instance by sending a probe ping to"
            + " /view/all/newJob endpoint as an anonymous user. An authenticated Jenkins instance"
            + " will show the createItem form, which allows the anonymous user to create arbitrary"
            + " jobs that could lead to RCE.",
    author = "Tsunami Team (tsunami-dev@google.com)",
    bootstrapModule = JenkinsExposedUiDetectorBootstrapModule.class)
public final class JenkinsExposedUiDetector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private final Clock utcClock;
  private final HttpClient httpClient;

  @Inject
  public JenkinsExposedUiDetector(@UtcClock Clock utcClock, HttpClient httpClient) {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient);
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("Starting exposed ui detection for Jenkins");
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
    // NOTE: Jenkins URL is case sensitive and trailing-slash sensitive!!
    String targetUri =
        NetworkServiceUtils.buildWebApplicationRootUrl(networkService) + "view/all/newJob";
    try {
      // This is a blocking call.
      HttpResponse response =
          httpClient.send(get(targetUri).withEmptyHeaders().build(), networkService);
      return response.status().isSuccess()
          // TODO(b/149479388): checking Jenkins string is not needed once we have plugin
          // matching logic.
          && response
              .bodyString()
              .map(body -> body.contains("Jenkins") && bodyContainsCreateItemForm(body))
              .orElse(false);
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Unable to query '%s'.", targetUri);
      return false;
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
                        .setValue("UNAUTHENTICATED_JENKINS_NEW_ITEM_CONSOLE"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("Unauthenticated Jenkins New Item Console")
                // TODO(b/147455413): determine CVSS score.
                .setDescription(
                    "Unauthenticated Jenkins instance allows anonymous users to create arbitrary"
                        + " projects, which usually leads to code downloading from the internet"
                        + " and remote code executions."))
        .build();
  }

  private static boolean bodyContainsCreateItemForm(String responseBody) {
    // An unauthenticated Jenkins instance will show a HTML form with id createItem when user visits
    // the /view/all/newJob endpoint.
    Elements createItemForm = Jsoup.parse(responseBody).select("form#createItem");
    if (createItemForm.isEmpty()) {
      logger.atInfo().log("Jenkins doesn't allow creating new jobs as anonymous user.");
      return false;
    } else {
      logger.atInfo().log(
          "Jenkins allows creating jobs as anonymous user, this will allow remote code execution!");
      return true;
    }
  }
}
