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
import static java.util.stream.Collectors.joining;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.google.common.flogger.GoogleLogger;
import com.google.tsunami.common.data.NetworkServiceUtils;
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
import com.google.tsunami.proto.CrawlConfig;
import com.google.tsunami.proto.CrawlResult;
import com.google.tsunami.proto.FingerprintingReport;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.ServiceContext;
import com.google.tsunami.proto.Software;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.Version;
import com.google.tsunami.proto.VersionSet;
import com.google.tsunami.proto.WebServiceContext;
import java.util.Collection;
import java.util.Optional;
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
  // TODO(b/154006875): make this configurable.
  private static final int MAX_ALLOWED_FAILED_REQUESTS = 20;
  private static final int MAX_ALLOWED_HTTP_REQUEST = 100;

  private final FingerprintRegistry fingerprintRegistry;
  private final Crawler crawler;
  private final SoftwareDetector softwareDetector;
  private final VersionDetector.Factory versionDetectorFactory;

  @Inject
  WebServiceFingerprinter(
      FingerprintRegistry fingerprintRegistry,
      Crawler crawler,
      SoftwareDetector softwareDetector,
      VersionDetector.Factory versionDetectorFactory) {
    this.fingerprintRegistry = checkNotNull(fingerprintRegistry);
    this.crawler = checkNotNull(crawler);
    this.softwareDetector = checkNotNull(softwareDetector);
    this.versionDetectorFactory = checkNotNull(versionDetectorFactory);
  }

  @Override
  public FingerprintingReport fingerprint(TargetInfo targetInfo, NetworkService networkService) {
    String startingUrl = NetworkServiceUtils.buildWebApplicationRootUrl(networkService);
    logger.atInfo().log("WebServiceFingerprinter start fingerprinting '%s'.", startingUrl);

    ImmutableSet<CrawlResult> crawlResults = crawlNetworkService(startingUrl, networkService);
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
    if (versionsBySoftware.isEmpty()) {
      logger.atInfo().log(
          "WebServiceFingerprinter failed to confirm running web application on '%s'.",
          startingUrl);
      return FingerprintingReport.newBuilder().addNetworkServices(networkService).build();
    } else {
      logger.atInfo().log(
          "WebServiceFingerprinter identified %d results for '%s'.",
          versionsBySoftware.size(), startingUrl);
      return FingerprintingReport.newBuilder()
          .addAllNetworkServices(
              versionsBySoftware.entrySet().stream()
                  .map(
                      entry ->
                          addWebServiceContext(networkService, entry.getKey(), entry.getValue()))
                  .collect(toImmutableList()))
          .build();
    }
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
              MAX_ALLOWED_FAILED_REQUESTS,
              MAX_ALLOWED_HTTP_REQUEST);
      versionsBySoftwareBuilder.put(software, versionDetector.detectVersions());
    }
    return versionsBySoftwareBuilder.build();
  }

  private static NetworkService addWebServiceContext(
      NetworkService networkService,
      DetectedSoftware detectedSoftware,
      DetectedVersion detectedVersion) {
    Software software =
        Software.newBuilder().setName(detectedSoftware.softwareIdentity().getSoftware()).build();
    VersionSet versionSet =
        VersionSet.newBuilder()
            .addAllVersions(
                detectedVersion.versions().stream()
                    .map(
                        version ->
                            Version.newBuilder()
                                .setFullVersionString(version.getFullName())
                                .build())
                    .collect(toImmutableList()))
            .build();
    WebServiceContext webServiceContext =
        WebServiceContext.newBuilder()
            .setApplicationRoot(detectedSoftware.rootPath())
            .setSoftware(software)
            .setVersionSet(versionSet)
            .build();
    return networkService.toBuilder()
        .setServiceContext(ServiceContext.newBuilder().setWebServiceContext(webServiceContext))
        .build();
  }

  private ImmutableSet<CrawlResult> crawlNetworkService(
      String seedingUrl, NetworkService networkService) {
    CrawlConfig crawlConfig =
        CrawlConfig.newBuilder()
            .addScopes(ScopeUtils.fromUrl(seedingUrl))
            .addSeedingUrls(seedingUrl)
            .setMaxDepth(3)
            .setNetworkService(networkService)
            .build();
    return crawler.crawl(crawlConfig);
  }
}
