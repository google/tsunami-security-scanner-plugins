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
package com.google.tsunami.plugins.detectors.exposedui.jupyter;

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

/** A {@link VulnDetector} that detects unauthenticated Jupyter Notebook shell page. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "JupyterExposedUiDetector",
    version = "0.1",
    description =
        "This detector checks whether a unauthenticated Jupyter Notebook is exposed. Jupyter"
            + " allows by design to run arbitrary code on the host machine. Having it exposed puts"
            + " the hosting VM at risk of RCE.",
    author = "Tsunami Team (tsunami-dev@google.com)",
    bootstrapModule = JupyterExposedUiDetectorBootstrapModule.class)

@ForWebService
public final class JupyterExposedUiDetector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  @VisibleForTesting
  static final String FINDING_RECOMMENDATION_TEXT = "If it is necessary to keep running this "
      + "instance of Jupyter, DO NOT expose it externally, in favor of using SSH tunnels to "
      + "access it. In addition, the service should only listen on localhost (127.0.0.1), and "
      + "consider restrict the access to the Jupyter Notebook using an authentication method. "
      + "See https://jupyter-notebook.readthedocs.io/en/stable/security.html";

  private final Clock utcClock;
  private final HttpClient httpClient;

  @Inject
  public JupyterExposedUiDetector(@UtcClock Clock utcClock, HttpClient httpClient) {
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
                    .setValue("JUPYTER_NOTEBOOK_EXPOSED_UI"))
            .setSeverity(Severity.CRITICAL)
            .setTitle("Jupyter Notebook Exposed Ui")
            // TODO(b/147455413): determine CVSS score.
            .setDescription("Jupyter Notebook is not password or token protected")
            .setRecommendation(FINDING_RECOMMENDATION_TEXT)
            .build());
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("Starting exposed ui detection for Jupyter Notebook");
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
    String targetUri =
        NetworkServiceUtils.buildWebApplicationRootUrl(networkService) + "terminals/1";
    try {
      // This is a blocking call.
      HttpResponse response =
          httpClient.send(get(targetUri).withEmptyHeaders().build(), networkService);
      return response.status().isSuccess()
          // TODO(b/147455413): checking Jupyter Notebook string is not needed once we have plugin
          // matching logic.
          // Newer version of Jupyter no longer has websocket in the body.
          && response
              .bodyString()
              .map(
                  body ->
                      body.contains("Jupyter Notebook")
                          && (body.contains("terminals/websocket/1")
                              || body.contains("jupyter-config-data"))
                          && !body.contains("authentication is enabled"))
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
        .setVulnerability(this.getAdvisories().get(0))
        .build();
  }
}
