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
import static com.google.common.collect.ImmutableSet.toImmutableSet;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.common.flogger.GoogleLogger;
import com.google.common.labs.collect.BiStream;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.UrlUtils;
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
import java.util.List;
import java.util.regex.Pattern;
import javax.inject.Inject;

/** A generic Path Traversal detector plugin. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "GenericPathTraversalDetector",
    version = "0.5",
    description = "This plugin detects generic Path Traversal vulnerabilities.",
    author = "Moritz Wilhelm (mzwm@google.com)",
    bootstrapModule = GenericPathTraversalDetectorBootstrapModule.class)
public final class GenericPathTraversalDetector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private static final ImmutableSet<InjectionPoint> INJECTION_POINTS =
      ImmutableSet.of(new PathParameterInjection(), new GetParameterInjection());
  private static final String RELATIVE_PATH_PREFIX = "../".repeat(29) + "..";
  private static final String ETC_PASSWD_PATH = "/etc/passwd";
  private static final Pattern ETC_PASSWD_PATTERN = Pattern.compile("root:x:0:0:");
  private final Clock utcClock;
  private final HttpClient httpClient;

  @Inject
  GenericPathTraversalDetector(@UtcClock Clock utcClock, HttpClient httpClient) {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient);
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
                .distinct()
                .filter(this::isExploitable)
                .collect(BiStream.groupingBy(PotentialExploit::networkService, toImmutableSet()))
                .toList((service, exploits) -> buildDetectionReport(targetInfo, service, exploits)))
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

  private ImmutableSet<PotentialExploit> injectPayloads(ExploitGenerator exploitGenerator) {
    String payload = UrlUtils.urlEncode(RELATIVE_PATH_PREFIX + ETC_PASSWD_PATH).get();
    return exploitGenerator.injectPayload(payload);
  }

  private ImmutableSet<PotentialExploit> generatePotentialExploits(NetworkService networkService) {
    List<CrawlResult> crawlResults =
        networkService.getServiceContext().getWebServiceContext().getCrawlResultsList();
    return crawlResults.stream()
        .filter(this::shouldFuzzCrawlResult)
        .map(crawlResult -> this.buildHttpRequestFromCrawlTarget(crawlResult.getCrawlTarget()))
        .map(targetRequest -> new ExploitGenerator(targetRequest, networkService, INJECTION_POINTS))
        .map(this::injectPayloads)
        .flatMap(Collection::stream)
        .collect(toImmutableSet());
  }

  private boolean isExploitable(PotentialExploit potentialExploit) {
    try {
      HttpResponse response =
          httpClient.send(potentialExploit.request(), potentialExploit.networkService());

      if (response.status().isSuccess() && response.bodyString().isPresent()) {
        return ETC_PASSWD_PATTERN.matcher(response.bodyString().get()).find();
      }
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Unable to query '%s'.", potentialExploit.request());
    }
    return false;
  }

  private ImmutableSet<AdditionalDetail> buildAdditionalDetails(
      ImmutableSet<PotentialExploit> exploits) {
    ImmutableSet.Builder<AdditionalDetail> additionalDetails = ImmutableSet.builder();
    for (PotentialExploit potentialExploit : exploits) {
      AdditionalDetail detail =
          AdditionalDetail.newBuilder()
              .setTextData(TextData.newBuilder().setText(potentialExploit.toString()).build())
              .build();
      additionalDetails.add(detail);
    }
    return additionalDetails.build();
  }

  private DetectionReport buildDetectionReport(
      TargetInfo targetInfo,
      NetworkService networkService,
      ImmutableSet<PotentialExploit> exploits) {
    return DetectionReport.newBuilder()
        .setTargetInfo(targetInfo)
        .setNetworkService(networkService)
        .setDetectionTimestamp(Timestamps.fromMillis(Instant.now(utcClock).toEpochMilli()))
        .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
        .setVulnerability(
            Vulnerability.newBuilder()
                .setMainId(
                    VulnerabilityId.newBuilder().setPublisher("GOOGLE").setValue("GENERIC_PT"))
                .setSeverity(Severity.MEDIUM)
                .setTitle(
                    String.format(
                        "Generic Path Traversal vulnerability at %s",
                        NetworkServiceUtils.buildWebApplicationRootUrl(networkService)))
                .setDescription(
                    "Generic Path Traversal vulnerability allowing to leak arbitrary files.")
                .setRecommendation(
                    "Do not accept user-controlled file paths or restrict file paths to a set of"
                        + " pre-defined paths. If the application is meant to let users define file"
                        + " names, apply `basename` or equivalent before handling the provided file"
                        + " name.")
                .addAdditionalDetails(
                    AdditionalDetail.newBuilder()
                        .setTextData(
                            TextData.newBuilder()
                                .setText(
                                    String.format(
                                        "Found %s distinct vulnerable configurations.",
                                        exploits.size()))))
                .addAllAdditionalDetails(this.buildAdditionalDetails(exploits)))
        .build();
  }
}
