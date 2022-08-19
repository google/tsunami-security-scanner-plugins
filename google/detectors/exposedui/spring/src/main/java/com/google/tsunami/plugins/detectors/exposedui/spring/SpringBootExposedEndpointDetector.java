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
package com.google.tsunami.plugins.detectors.exposedui.spring;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.base.Preconditions.checkState;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.tsunami.common.net.UrlUtils.removeLeadingSlashes;
import static com.google.tsunami.common.net.UrlUtils.removeTrailingSlashes;
import static com.google.tsunami.common.net.http.HttpRequest.head;

import com.google.auto.value.AutoValue;
import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.common.net.HttpHeaders;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.config.annotations.ConfigProperties;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpResponse;
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
import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;
import javax.inject.Inject;
import okhttp3.HttpUrl;

/** A {@link VulnDetector} that detects exposed Spring Boot Actuator endpoints. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "SpringBootExposedEndpointDetector",
    version = "0.1",
    description =
        "This detector checks whether sensitive Actuator endpoints of a Spring Boot application is"
            + " exposed. Some of the default endpoints like /heapdump may expose sensitive"
            + " information while others like /env might lead to RCE. Currently this plugin only"
            + " checks for /heapdump endpoint.",
    author = "Tsunami Team (tsunami-dev@google.com)",
    bootstrapModule = SpringBootExposedEndpointDetectorBootstrapModule.class)
public final class SpringBootExposedEndpointDetector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  private static final Pattern HEAPDUMP_FILE_PATTERN =
      Pattern.compile("heapdump\\d{4}-\\d{2}-\\d{2}-\\d{2}-\\d{2}.*\\.hprof");

  private final Clock utcClock;
  private final HttpClient httpClient;
  private final Configs configs;

  @Inject
  public SpringBootExposedEndpointDetector(
      @UtcClock Clock utcClock, HttpClient httpClient, Configs configs) {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient);
    this.configs = checkNotNull(configs);
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("Starting exposed ui detection for Spring Boot Actuator endpoint.");
    return DetectionReportList.newBuilder()
        .addAllDetectionReports(
            matchedServices.stream()
                .filter(NetworkServiceUtils::isWebService)
                .map(this::checkEndpointForNetworkService)
                .filter(EndpointProbingResult::isVulnerable)
                .map(probingResult -> buildDetectionReport(targetInfo, probingResult))
                .collect(toImmutableList()))
        .build();
  }

  private EndpointProbingResult checkEndpointForNetworkService(NetworkService networkService) {
    String rootUrl = NetworkServiceUtils.buildWebApplicationRootUrl(networkService);
    // Generate all potential heapdump URLs to check from the application root url.
    ImmutableList<HttpUrl> heapDumpUrls = appendHeapDumpEndpoint(HttpUrl.parse(rootUrl));

    // Report vulnerability if any of the potential endpoints is exposed.
    for (HttpUrl heapDumpUrl : heapDumpUrls) {
      EndpointProbingResult probingResult = probeHeapdumpEndpoint(heapDumpUrl, networkService);
      if (probingResult.isVulnerable()) {
        logger.atInfo().log(
            "Identified exposed Spring Boot heapdump endpoint at '%s'.", heapDumpUrl);
        return probingResult;
      }
    }
    return EndpointProbingResult.invulnerableForNetworkService(networkService);
  }

  private ImmutableList<HttpUrl> appendHeapDumpEndpoint(HttpUrl url) {
    ImmutableList<String> endpointPrefixes =
        configs.endpointPrefixes == null
            // For Spring 1x, actuator endpoints are registered under the root URL, and in 2x they
            // are moved to the "/actuator/" base path.
            ? ImmutableList.of("", "/actuator/")
            : ImmutableList.copyOf(configs.endpointPrefixes);
    return endpointPrefixes.stream()
        .map(
            prefix ->
                url.newBuilder()
                    .addPathSegments(removeLeadingSlashes(removeTrailingSlashes(prefix)))
                    .addPathSegments("heapdump")
                    .build())
        .collect(toImmutableList());
  }

  // Example HTTP HEAD response from /heapdump:
  //
  // HTTP/1.1 200
  // X-Application-Context: application
  // Content-Disposition:
  //     attachment; filename="heapdump2020-06-15-09-20-live3506123733943811331.hprof.gz"
  // Content-Type: application/octet-stream
  // Content-Length: 7407107
  // Date: Mon, 15 Jun 2020 16:20:04 GMT
  private EndpointProbingResult probeHeapdumpEndpoint(
      HttpUrl endpointUrl, NetworkService networkService) {
    try {
      HttpResponse response =
          httpClient.send(head(endpointUrl).withEmptyHeaders().build(), networkService);
      // 200 response.
      boolean isVulnerable =
          response.status().isSuccess()
              // Content-Disposition header has matching heapdump filename.
              && response
                  .headers()
                  .get(HttpHeaders.CONTENT_DISPOSITION)
                  .map(headerValue -> HEAPDUMP_FILE_PATTERN.matcher(headerValue).find())
                  .orElse(false);
      if (!isVulnerable) {
        return EndpointProbingResult.invulnerableForNetworkService(networkService);
      }

      return EndpointProbingResult.builder()
          .setIsVulnerable(true)
          .setNetworkService(networkService)
          .setVulnerableEndpoint(endpointUrl.toString())
          .setVulnerableEndpointResponse(response)
          .build();
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Unable to query endpoint: '%s'.", endpointUrl);
      return EndpointProbingResult.invulnerableForNetworkService(networkService);
    }
  }

  private DetectionReport buildDetectionReport(
      TargetInfo scannedTarget, EndpointProbingResult endpointProbingResult) {
    return DetectionReport.newBuilder()
        .setTargetInfo(scannedTarget)
        .setNetworkService(endpointProbingResult.networkService())
        .setDetectionTimestamp(Timestamps.fromMillis(Instant.now(utcClock).toEpochMilli()))
        .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
        .setVulnerability(
            Vulnerability.newBuilder()
                .setMainId(
                    VulnerabilityId.newBuilder()
                        .setPublisher("GOOGLE")
                        .setValue("EXPOSED_SPRING_BOOT_ACTUATOR_ENDPOINT"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("Exposed Spring Boot Actuator Endpoint")
                .setDescription(
                    "Spring Boot applications have several built-in Actuator endpoints enabled by"
                        + " default. For example, '/env' endpoint exposes all properties from"
                        + " Spring's ConfigurableEnvironment including system environment"
                        + " variables, and '/heapdump' will dump the entire memory of the server"
                        + " into a file. Exposing these endpoints could potentially leak sensitive"
                        + " information to any unauthenticated users.")
                .setRecommendation("Disable public access to Actuator endpoints.")
                .addAdditionalDetails(buildAdditionalDetail(endpointProbingResult)))
        .build();
  }

  private static AdditionalDetail buildAdditionalDetail(EndpointProbingResult probingResult) {
    checkState(probingResult.vulnerableEndpoint().isPresent());
    checkState(probingResult.vulnerableEndpointResponse().isPresent());
    return AdditionalDetail.newBuilder()
        .setTextData(
            TextData.newBuilder()
                .setText(
                    String.format(
                        "Vulnerable endpoint: '%s'", probingResult.vulnerableEndpoint().get())))
        .build();
  }

  @ConfigProperties("plugins.google.detector.exposed_ui.spring")
  static final class Configs {
    // The path prefixes to be added for the Spring Boot Actuator endpoint.
    List<String> endpointPrefixes;
  }

  @AutoValue
  abstract static class EndpointProbingResult {
    abstract boolean isVulnerable();
    abstract NetworkService networkService();
    abstract Optional<String> vulnerableEndpoint();
    abstract Optional<HttpResponse> vulnerableEndpointResponse();

    static Builder builder() {
      return new AutoValue_SpringBootExposedEndpointDetector_EndpointProbingResult.Builder();
    }

    static EndpointProbingResult invulnerableForNetworkService(NetworkService networkService) {
      return builder().setIsVulnerable(false).setNetworkService(networkService).build();
    }

    @AutoValue.Builder
    abstract static class Builder {
      abstract Builder setIsVulnerable(boolean value);
      abstract Builder setNetworkService(NetworkService value);
      abstract Builder setVulnerableEndpoint(String value);
      abstract Builder setVulnerableEndpointResponse(HttpResponse value);

      abstract EndpointProbingResult build();
    }
  }
}
