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
import static com.google.common.collect.ImmutableSetMultimap.toImmutableSetMultimap;
import static com.google.tsunami.common.net.UrlUtils.removeLeadingSlashes;
import com.google.common.base.Ascii;
import com.google.common.base.Strings;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.ImmutableSetMultimap;
import com.google.common.flogger.GoogleLogger;
import com.google.common.io.Files;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpStatus;
import com.google.tsunami.plugin.PluginType;
import com.google.tsunami.plugin.ServiceFingerprinter;
import com.google.tsunami.plugin.annotations.ForWebService;
import com.google.tsunami.plugin.annotations.PluginInfo;
import com.google.tsunami.plugins.fingerprinters.web.common.FingerprintUtils;
import com.google.tsunami.plugins.fingerprinters.web.common.WebConstant;
import com.google.tsunami.plugins.fingerprinters.web.crawl.Crawler;
import com.google.tsunami.plugins.fingerprinters.web.crawl.ScopeUtils;
import com.google.tsunami.plugins.fingerprinters.web.detection.SoftwareDetector;
import com.google.tsunami.plugins.fingerprinters.web.detection.SoftwareDetector.DetectedSoftware;
import com.google.tsunami.plugins.fingerprinters.web.detection.VersionDetector;
import com.google.tsunami.plugins.fingerprinters.web.detection.VersionDetector.DetectedVersion;
import com.google.tsunami.plugins.fingerprinters.web.proto.Hash;
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
import okhttp3.HttpUrl;

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

  private final Crawler crawler;
  private final SoftwareDetector softwareDetector;
  private final VersionDetector versionDetector;
  private final WebServiceFingerprinterConfigs configs;

  private static final ImmutableSet<String> IGNORED_EXTENTIONS = WebConstant.IGNORED_EXTENTIONS;

  @Inject
  WebServiceFingerprinter(
      Crawler crawler,
      SoftwareDetector softwareDetector,
      VersionDetector versionDetector,
      WebServiceFingerprinterConfigs configs) {
    this.crawler = checkNotNull(crawler);
    this.softwareDetector = checkNotNull(softwareDetector);
    this.versionDetector = checkNotNull(versionDetector);
    this.configs = checkNotNull(configs);
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

    ImmutableSetMultimap<String, Hash> path2hash = crawlResults.stream()
            .filter(crawlResult -> HttpStatus.fromCode(crawlResult.getResponseCode()).isSuccess())
            .filter(crawlResult -> !isIgnoredCrawledFile(getPathFromCrawlResult(crawlResult)))
            .collect(
                    toImmutableSetMultimap(
                            crawlResult ->
                                    removeLeadingSlashes(getPathFromCrawlResult(crawlResult)),
                            FingerprintUtils::hashCrawlResult));


    WebServiceContext.Builder webserviceContextBuilder = WebServiceContext.newBuilder();
    //进行软件检测和版本检测
    DetectedSoftware detectedSoftware = softwareDetector.detectSoftware(path2hash);
    if (Optional.ofNullable(detectedSoftware).isPresent()) {
      Software software =
              Software.newBuilder().setName(detectedSoftware.softwareIdentity().getSoftware()).build();
      webserviceContextBuilder.setApplicationRoot(detectedSoftware.rootPath());
      webserviceContextBuilder.setSoftware(software);

      //用detectedSoftware中命中的hash信息去匹配版本
      DetectedVersion detectedVersion = versionDetector.detectVersions(detectedSoftware);
      if (Optional.ofNullable(detectedVersion).isPresent()) {
        VersionSet versionSet =
                VersionSet.newBuilder()
                        .addAllVersions(
                                detectedVersion.versions().stream()
                                        .map(version -> Version.newBuilder()
                                                .setType(VersionType.NORMAL)
                                                .setFullVersionString(version.getFullName())
                                                .build())
                                        .collect(toImmutableList()))
                        .build();
        webserviceContextBuilder.setVersionSet(versionSet);
      }
    }
    /**FingerprintingReport 添加 networkService -> servicecontext -> webserviceContext -> software -> version*/


    FingerprintingReport.Builder reportBuilder = FingerprintingReport.newBuilder();
    ServiceContext.Builder serviceContextBuilder = ServiceContext.newBuilder();
    serviceContextBuilder.setWebServiceContext(webserviceContextBuilder.build());

    NetworkService.Builder networkServiceBuilder = networkService.toBuilder().setServiceContext(serviceContextBuilder.build());
    reportBuilder.addNetworkServices(networkServiceBuilder.build());

    return reportBuilder.build();
  }


  private String getPathFromCrawlResult(CrawlResult crawlResult) {
    HttpUrl url = HttpUrl.get(crawlResult.getCrawlTarget().getUrl());
    String query = url.encodedQuery();
    if (Strings.isNullOrEmpty(query)) {
      return url.encodedPath();
    }
    return url.encodedPath() + "?" + query;
  }

  /**
   * TODO 此处后续应该抓取的时候就去掉一些没用的后缀
   * @param seedingUrl
   * @param networkService
   * @param shouldEnforceScopeCheck
   * @return
   */
  private ImmutableSet<CrawlResult> crawlNetworkService(
      String seedingUrl, NetworkService networkService, boolean shouldEnforceScopeCheck) {
    CrawlConfig crawlConfig =
        CrawlConfig.newBuilder()
            .addScopes(ScopeUtils.fromUrl(seedingUrl))
            .setShouldEnforceScopeCheck(shouldEnforceScopeCheck)
            .addSeedingUrls(seedingUrl)
            .setMaxDepth(3)
            .setNetworkService(networkService)
            .build();
    return crawler.crawl(crawlConfig);
  }

  private static boolean isIgnoredCrawledFile(String relativePath) {
    // Use the relative path so that parent directory names are not checked.
    String extension = Files.getFileExtension(Ascii.toLowerCase(relativePath));

    return extension.isEmpty() || IGNORED_EXTENTIONS.contains(extension);
  }
}
