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
package com.google.tsunami.plugins.fingerprinters.web;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.common.collect.ImmutableSet.toImmutableSet;
import static com.google.tsunami.common.net.http.HttpRequest.get;
import static java.util.stream.Collectors.joining;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.google.common.flogger.GoogleLogger;
import com.google.tsunami.common.data.NetworkEndpointUtils;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpResponse;
import com.google.tsunami.common.net.http.HttpStatus;
import com.google.tsunami.plugin.PluginType;
import com.google.tsunami.plugin.ServiceFingerprinter;
import com.google.tsunami.plugin.annotations.ForWebService;
import com.google.tsunami.plugin.annotations.PluginInfo;
import com.google.tsunami.plugins.fingerprinters.web.crawl.Crawler;
import com.google.tsunami.plugins.fingerprinters.web.crawl.ScopeUtils;
import com.google.tsunami.plugins.fingerprinters.web.data.FingerprintData;
import com.google.tsunami.plugins.fingerprinters.web.data.FingerprintRegistry;
import com.google.tsunami.plugins.fingerprinters.web.detection.SoftwareDetector;
import com.google.tsunami.plugins.fingerprinters.web.detection.SoftwareDetector.DetectedSoftware;
import com.google.tsunami.plugins.fingerprinters.web.detection.VersionDetector;
import com.google.tsunami.plugins.fingerprinters.web.detection.VersionDetector.DetectedVersion;
import com.google.tsunami.plugins.fingerprinters.web.proto.SoftwareIdentity;
import com.google.tsunami.proto.CrawlConfig;
import com.google.tsunami.proto.CrawlResult;
import com.google.tsunami.proto.FingerprintingReport;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.ServiceContext;
import com.google.tsunami.proto.Software;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.Version;
import com.google.tsunami.proto.Version.VersionType;
import com.google.tsunami.proto.VersionSet;
import com.google.tsunami.proto.WebServiceContext;
import java.io.IOException;
import java.util.Collection;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import javax.inject.Inject;

/** A {@link ServiceFingerprinter} plugin that fingerprints web applications. */
@PluginInfo(
    type = PluginType.SERVICE_FINGERPRINT,
    name = "WebServiceFingerprinter",
    version = "0.1",
    description = "Identifies web application and versions.",
    author = "Tsunami Team (tsunami-dev@google.com)",
    bootstrapModule = WebServiceFingerprinterBootstrapModule.class)
@ForWebService
public final class WebServiceFingerprinter implements ServiceFingerprinter {

  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private final FingerprintRegistry fingerprintRegistry;
  private final Crawler crawler;
  private final SoftwareDetector softwareDetector;
  private final VersionDetector.Factory versionDetectorFactory;
  private final WebServiceFingerprinterConfigs configs;
  private final HttpClient httpClient;

  @Inject
  WebServiceFingerprinter(
      FingerprintRegistry fingerprintRegistry,
      Crawler crawler,
      SoftwareDetector softwareDetector,
      VersionDetector.Factory versionDetectorFactory,
      WebServiceFingerprinterConfigs configs,
      HttpClient httpClient) {
    this.fingerprintRegistry = checkNotNull(fingerprintRegistry);
    this.crawler = checkNotNull(crawler);
    this.softwareDetector = checkNotNull(softwareDetector);
    this.versionDetectorFactory = checkNotNull(versionDetectorFactory);
    this.configs = checkNotNull(configs);
    this.httpClient = checkNotNull(httpClient);
  }

  @Override
  public FingerprintingReport fingerprint(TargetInfo targetInfo, NetworkService networkService) {
    String startingUrl = NetworkServiceUtils.buildWebApplicationRootUrl(networkService);
    logger.atInfo().log("WebServiceFingerprinter start fingerprinting '%s'.", startingUrl);

    ImmutableSet<CrawlResult> crawlResults =
        crawlNetworkService(startingUrl, networkService, configs.shouldEnforceCrawlingScopeCheck());
    logger.atInfo().log(
        "WebServiceFingerprinter discovered %d different files on '%s'.",
        crawlResults.size(), NetworkServiceUtils.buildWebApplicationRootUrl(networkService));

    ImmutableSet<DetectedSoftware> detectedSoftware = softwareDetector.detectSoftware(crawlResults);
    logger.atInfo().log(
        "WebServiceFingerprinter discovered %d potential applications for '%s': [%s].",
        detectedSoftware.size(),
        startingUrl,
        detectedSoftware.stream()
            .map(software -> software.softwareIdentity().getSoftware())
            .collect(joining(",")));

    ImmutableMap<DetectedSoftware, DetectedVersion> versionsBySoftware =
        detectSoftwareVersions(detectedSoftware, networkService);

    ImmutableSet<CrawlResult> crawlResultsUnderRecordingLimit =
        crawlResults.stream()
            .filter(
                crawlResult ->
                    crawlResult.getContent().size() < configs.getMaxRecordingContentSize())
            .filter(
                crawlResult ->
                    !configs.getContentTypeExclusions().contains(crawlResult.getContentType()))
            .collect(toImmutableSet());

    if (versionsBySoftware.isEmpty()) {
      logger.atInfo().log(
          "WebServiceFingerprinter failed to confirm running web application on '%s' using existing"
              + " hashes. Try custom heuristics instead",
          startingUrl);
      return fingerprintWithCustomHeuristics(
          networkService, startingUrl, crawlResultsUnderRecordingLimit);
    } else {
      logger.atInfo().log(
          "WebServiceFingerprinter identified %d results for '%s'.",
          versionsBySoftware.size(), startingUrl);
      return FingerprintingReport.newBuilder()
          .addAllNetworkServices(
              versionsBySoftware.entrySet().stream()
                  .map(
                      entry ->
                          addWebServiceContext(
                              networkService,
                              Optional.of(entry.getKey()),
                              Optional.of(entry.getValue()),
                              crawlResultsUnderRecordingLimit))
                  .collect(toImmutableList()))
          .build();
    }
  }

  private FingerprintingReport fingerprintWithCustomHeuristics(
      NetworkService networkService, String startingUrl, ImmutableSet<CrawlResult> crawlResults) {
    ImmutableSet<DetectedSoftware> detectedSoftware =
        detectSoftwareByCustomHeuristics(networkService, startingUrl);

    if (detectedSoftware.isEmpty()) {
      logger.atInfo().log(
          "WebServiceFingerprinter failed to confirm running web application on '%s' using custom"
              + " heuristics either.",
          startingUrl);
      return FingerprintingReport.newBuilder()
          .addNetworkServices(
              addWebServiceContext(
                  networkService, Optional.empty(), Optional.empty(), crawlResults))
          .build();
    }

    logger.atInfo().log(
        "WebServiceFingerprinter discovered %d potential applications for '%s': [%s] using custom"
            + " heuristics.",
        detectedSoftware.size(),
        startingUrl,
        detectedSoftware.stream()
            .map(software -> software.softwareIdentity().getSoftware())
            .collect(joining(",")));
    return FingerprintingReport.newBuilder()
        .addAllNetworkServices(
            detectedSoftware.stream()
                .map(
                    software ->
                        addWebServiceContext(
                            // Overwrite service name
                            networkService.toBuilder()
                                .setServiceName(software.softwareIdentity().getSoftware())
                                .build(),
                            Optional.of(software),
                            Optional.empty(),
                            crawlResults))
                .collect(toImmutableList()))
        .build();
  }

  private ImmutableMap<DetectedSoftware, DetectedVersion> detectSoftwareVersions(
      Collection<DetectedSoftware> detectedSoftware, NetworkService networkService) {
    ImmutableMap.Builder<DetectedSoftware, DetectedVersion> versionsBySoftwareBuilder =
        ImmutableMap.builder();
    for (DetectedSoftware software : detectedSoftware) {
      Optional<FingerprintData> fingerprintData =
          fingerprintRegistry.getFingerprintData(software.softwareIdentity());
      if (!fingerprintData.isPresent()) {
        logger.atSevere().log(
            "No fingerprint data for '%s'.", software.softwareIdentity().getSoftware());
        continue;
      }

      VersionDetector versionDetector =
          versionDetectorFactory.create(
              networkService,
              fingerprintData.get(),
              software,
              configs.getMaxFailedSiftingRequests(),
              configs.getMaxAllowedSiftingRequest());
      versionsBySoftwareBuilder.put(software, versionDetector.detectVersions());
    }
    return versionsBySoftwareBuilder.build();
  }

  private static NetworkService addWebServiceContext(
      NetworkService networkService,
      Optional<DetectedSoftware> detectedSoftware,
      Optional<DetectedVersion> detectedVersion,
      ImmutableSet<CrawlResult> crawlResults) {
    WebServiceContext.Builder webServiceContextBuilder =
        WebServiceContext.newBuilder().addAllCrawlResults(crawlResults);
    detectedSoftware.ifPresent(
        software ->
            webServiceContextBuilder
                .setApplicationRoot(software.rootPath())
                .setSoftware(
                    Software.newBuilder().setName(software.softwareIdentity().getSoftware())));
    detectedVersion.ifPresent(
        version ->
            webServiceContextBuilder.setVersionSet(
                VersionSet.newBuilder()
                    .addAllVersions(
                        version.versions().stream()
                            .map(
                                v ->
                                    Version.newBuilder()
                                        .setType(VersionType.NORMAL)
                                        .setFullVersionString(v.getFullName())
                                        .build())
                            .collect(toImmutableList()))
                    .build()));
    return networkService.toBuilder()
        .setServiceContext(
            ServiceContext.newBuilder().setWebServiceContext(webServiceContextBuilder.build()))
        .build();
  }

  private ImmutableSet<CrawlResult> crawlNetworkService(
      String seedingUrl, NetworkService networkService, boolean shouldEnforceScopeCheck) {
    CrawlConfig crawlConfig =
        CrawlConfig.newBuilder()
            .addScopes(ScopeUtils.fromUrl(seedingUrl))
            .setShouldEnforceScopeCheck(shouldEnforceScopeCheck)
            .addSeedingUrls(seedingUrl)
            // TODO: b/293337245 This is a Temporary change to include jenkins login url in seeding
            // urls. This will be replaced by making seeding url configurable through cli options
            // instead.
            .addSeedingUrls(seedingUrl + "/login?from=%2F")
            .setMaxDepth(3)
            .setNetworkEndpoint(networkService.getNetworkEndpoint())
            .build();
    return crawler.crawl(crawlConfig);
  }

  private ImmutableSet<DetectedSoftware> detectSoftwareByCustomHeuristics(
      NetworkService networkService, String startingUrl) {
    HashSet<DetectedSoftware> detectedSoftware = new HashSet<>();

    checkForMlflow(detectedSoftware, networkService, startingUrl);
    return ImmutableSet.copyOf(detectedSoftware);
  }

  private void checkForMlflow(
      Set<DetectedSoftware> software, NetworkService networkService, String startingUrl) {
    logger.atInfo().log("probing Mlflow ping - custom fingerprint phase");

    // We want to test weak credentials against mlflow versions above 2.5 which has basic
    // authentication module.these versions return a 401 status code and a link to documentation
    // about how to authenticate.
    var uriAuthority = NetworkEndpointUtils.toUriAuthority(networkService.getNetworkEndpoint());
    var pingApiUrl = String.format("http://%s/%s", uriAuthority, "ping");
    try {
      HttpResponse apiPingResponse = httpClient.send(get(pingApiUrl).withEmptyHeaders().build());

      if (apiPingResponse.status() != HttpStatus.UNAUTHORIZED
          || apiPingResponse.bodyString().isEmpty()) {
        return;
      }

      if (apiPingResponse
          .bodyString()
          .get()
          .contains(
              "You are not authenticated. Please see "
                  + "https://www.mlflow.org/docs/latest/auth/index.html"
                  + "#authenticating-to-mlflow "
                  + "on how to authenticate")) {
        software.add(
            DetectedSoftware.builder()
                .setSoftwareIdentity(SoftwareIdentity.newBuilder().setSoftware("mlflow").build())
                .setRootPath(startingUrl)
                .setContentHashes(ImmutableMap.of())
                .build());
      }
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Unable to query '%s'.", pingApiUrl);
    }
  }
}
