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
package com.google.tsunami.plugins.detectors.directorytraversal.genericpathtraversaldetector;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.common.collect.ImmutableSet.toImmutableSet;
import static java.util.Comparator.comparing;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.common.flogger.GoogleLogger;
import com.google.common.labs.collect.BiStream;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpMethod;
import com.google.tsunami.common.net.http.HttpRequest;
import com.google.tsunami.common.net.http.HttpResponse;
import com.google.tsunami.common.time.UtcClock;
import com.google.tsunami.plugin.PluginType;
import com.google.tsunami.plugin.VulnDetector;
import com.google.tsunami.plugin.annotations.PluginInfo;
import com.google.tsunami.proto.AdditionalDetail;
import com.google.tsunami.proto.CrawlResult;
import com.google.tsunami.proto.CrawlTarget;
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
import java.util.Collection;
import java.util.Optional;
import java.util.regex.Pattern;
import javax.inject.Inject;

/** A generic Path Traversal detector plugin. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "GenericPathTraversalDetector",
    version = "1.4",
    description = "This plugin detects generic Path Traversal vulnerabilities.",
    author = "Moritz Wilhelm (mzwm@google.com)",
    bootstrapModule = GenericPathTraversalDetectorBootstrapModule.class)
public final class GenericPathTraversalDetector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private static final Pattern ETC_PASSWD_PATTERN = Pattern.compile("root:x:0:0:");

  @VisibleForTesting
  static final String FINDING_DESCRIPTION_TEXT =
      "Generic Path Traversal vulnerability allows arbitrary files leaks, see "
          + "https://owasp.org/www-community/attacks/Path_Traversal";

  private final Clock utcClock;
  private final HttpClient httpClient;
  private final GenericPathTraversalDetectorConfig config;

  @Inject
  GenericPathTraversalDetector(
      @UtcClock Clock utcClock, HttpClient httpClient, GenericPathTraversalDetectorConfig config) {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient);
    this.config = checkNotNull(config);
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("GenericPathTraversalDetector starts detecting.");

    return DetectionReportList.newBuilder()
        .addAllDetectionReports(
            matchedServices.stream()
                .filter(NetworkServiceUtils::isWebService)
                .map(this::generatePotentialExploits)
                .flatMap(Collection::stream)
                .sorted(
                    comparing(PotentialExploit::priority, PotentialExploit.Priority.COMPARATOR)
                        .thenComparing((PotentialExploit exploit) -> exploit.request().url()))
                .distinct()
                .limit(config.maxExploitsToTest())
                .map(this::checkExploitabilty)
                .filter(Optional::isPresent)
                .map(Optional::get)
                .collect(
                    BiStream.groupingBy(
                        (Detection detection) -> detection.exploit().networkService(),
                        toImmutableSet()))
                .toList(
                    (service, detections) -> buildDetectionReport(targetInfo, service, detections)))
        .build();
  }

  @Override
  public ImmutableList<Vulnerability> getAdvisories() {
    return ImmutableList.of(getAdvisory(null, ImmutableSet.of()));
  }

  Vulnerability getAdvisory(
      AdditionalDetail details, ImmutableSet<AdditionalDetail> additionalDetails) {
    return Vulnerability.newBuilder()
        .setMainId(VulnerabilityId.newBuilder().setPublisher("GOOGLE").setValue("GENERIC_PT"))
        .setSeverity(Severity.MEDIUM)
        .setTitle("Generic Path Traversal Vulnerability")
        .setDescription(FINDING_DESCRIPTION_TEXT)
        .setRecommendation(
            "Do not accept user-controlled file paths or restrict file paths to a set of"
                + " pre-defined paths. If the application is meant to let users define file"
                + " names, apply `basename` or equivalent before handling the provided file"
                + " name.")
        .addAdditionalDetails(details)
        .addAllAdditionalDetails(additionalDetails)
        .build();
  }

  private boolean shouldFuzzCrawlResult(CrawlResult crawlResult) {
    int responseCode = crawlResult.getResponseCode();
    CrawlTarget crawlTarget = crawlResult.getCrawlTarget();
    return (responseCode < 300 || responseCode >= 400) && crawlTarget.getHttpMethod().equals("GET");
  }

  private HttpRequest buildHttpRequestFromCrawlTarget(CrawlTarget crawlTarget) {
    return HttpRequest.builder()
        .setMethod(HttpMethod.valueOf(crawlTarget.getHttpMethod()))
        .setUrl(crawlTarget.getUrl())
        .withEmptyHeaders()
        .build();
  }

  private ImmutableList<PotentialExploit> injectPayloads(ExploitGenerator exploitGenerator) {
    ImmutableList.Builder<PotentialExploit> exploits = ImmutableList.builder();
    for (String payload : this.config.payloads()) {
      exploits.addAll(exploitGenerator.injectPayload(payload));
    }
    return exploits.build();
  }

  private ImmutableList<PotentialExploit> generatePotentialExploits(NetworkService networkService) {
    return networkService.getServiceContext().getWebServiceContext().getCrawlResultsList().stream()
        .filter(this::shouldFuzzCrawlResult)
        .map(CrawlResult::getCrawlTarget)
        .sorted(comparing(CrawlTarget::getUrl))
        .limit(config.maxCrawledUrlsToFuzz())
        .map(this::buildHttpRequestFromCrawlTarget)
        .map(request -> new ExploitGenerator(request, networkService, config.injectionPoints()))
        .map(this::injectPayloads)
        .flatMap(Collection::stream)
        .collect(toImmutableList());
  }

  private Optional<Detection> checkExploitabilty(PotentialExploit potentialExploit) {
    try {
      HttpResponse response =
          httpClient.send(potentialExploit.request(), potentialExploit.networkService());

      if (response.bodyString().isPresent()
          && ETC_PASSWD_PATTERN.matcher(response.bodyString().get()).find()) {
        return Optional.of(Detection.create(potentialExploit, response));
      }
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Unable to query '%s'.", potentialExploit.request());
    }
    return Optional.empty();
  }

  private ImmutableSet<AdditionalDetail> buildAdditionalDetails(
      ImmutableSet<Detection> detections) {
    ImmutableSet.Builder<AdditionalDetail> additionalDetails = ImmutableSet.builder();
    for (Detection detection : detections) {
      AdditionalDetail detail =
          AdditionalDetail.newBuilder()
              .setTextData(TextData.newBuilder().setText(detection.toString()).build())
              .build();
      additionalDetails.add(detail);
    }
    return additionalDetails.build();
  }

  private DetectionReport buildDetectionReport(
      TargetInfo targetInfo, NetworkService networkService, ImmutableSet<Detection> detections) {
    return DetectionReport.newBuilder()
        .setTargetInfo(targetInfo)
        .setNetworkService(networkService)
        .setDetectionTimestamp(Timestamps.fromMillis(Instant.now(utcClock).toEpochMilli()))
        .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
        .setVulnerability(
            getAdvisory(
                AdditionalDetail.newBuilder()
                    .setTextData(
                        TextData.newBuilder()
                            .setText(
                                String.format(
                                    "Found %s distinct vulnerable configurations.",
                                    detections.size())))
                    .build(),
                this.buildAdditionalDetails(detections)))
        .build();
  }
}
