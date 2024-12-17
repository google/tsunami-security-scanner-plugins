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
package com.google.tsunami.plugins.fingerprinters.web.detection;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableMap.toImmutableMap;
import static java.lang.Math.min;

import com.google.auto.value.AutoValue;
import com.google.common.base.Joiner;
import com.google.common.collect.HashMultiset;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.ImmutableSetMultimap;
import com.google.common.collect.Iterables;
import com.google.common.collect.Lists;
import com.google.common.collect.Streams;
import com.google.common.flogger.GoogleLogger;
import com.google.tsunami.plugins.fingerprinters.web.common.FingerprintUtils;
import com.google.tsunami.plugins.fingerprinters.web.data.FingerprintData;
import com.google.tsunami.plugins.fingerprinters.web.data.FingerprintRegistry;
import com.google.tsunami.plugins.fingerprinters.web.proto.Hash;
import com.google.tsunami.plugins.fingerprinters.web.proto.SoftwareIdentity;
import com.google.tsunami.proto.CrawlResult;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;
import javax.inject.Inject;
import okhttp3.HttpUrl;

/** Identifies the running software based on the crawled web contents. */
public final class SoftwareDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private final FingerprintRegistry fingerprintRegistry;

  @Inject
  SoftwareDetector(FingerprintRegistry fingerprintRegistry) {
    this.fingerprintRegistry = checkNotNull(fingerprintRegistry);
  }

  /**
   * Detect potential software for a given collection of web crawling results.
   *
   * <p>This method performs the software detection in the following steps:
   *
   * <ol>
   *   <li>Calculate hashes of each crawling result
   *   <li>Match the crawl result hashes against all known software hashes to guess potential
   *       software for the given crawl results. This step could generate multiple software matches
   *       because of common libraries that could potentially be used across software.
   *   <li>Finally for each identified software, try to locate the root path of the application.
   * </ol>
   *
   * @param crawlResults a collection of web crawling results.
   * @return the detected software set based on the crawling results.
   */
  public ImmutableSet<DetectedSoftware> detectSoftware(Collection<CrawlResult> crawlResults) {
    logger.atInfo().log("Trying to detect potential software for the scan target.");
    ImmutableMap<CrawlResult, Hash> crawlResultHashes =
        crawlResults.stream()
            .collect(toImmutableMap(Function.identity(), FingerprintUtils::hashCrawlResult));
    ImmutableSetMultimap<SoftwareIdentity, CrawlResult> crawlResultsBySoftware =
        matchPotentialSoftware(crawlResultHashes);

    if (crawlResultsBySoftware.isEmpty()) {
      logger.atWarning().log("No known software found.");
      return ImmutableSet.of();
    }

    ImmutableSet.Builder<DetectedSoftware> detectedSoftwareBuilder = ImmutableSet.builder();
    for (SoftwareIdentity softwareIdentity : crawlResultsBySoftware.keySet()) {
      ImmutableMap<CrawlResult, Hash> contentHashes =
          crawlResultsBySoftware.get(softwareIdentity).stream()
              .collect(toImmutableMap(Function.identity(), crawlResultHashes::get));
      if (!hasGloballyUniqueHash(contentHashes)) {
        logger.atInfo().log(
            "All detected hashes for '%s' are potentially common libs. Ignored.",
            softwareIdentity.getSoftware());
        continue;
      }

      String rootPath = findRootPath(softwareIdentity, contentHashes);
      if (rootPath.isEmpty()) {
        logger.atInfo().log(
            "%s likely running somewhere, but root path unknown.", softwareIdentity.getSoftware());
      } else {
        logger.atInfo().log(
            "Software %s is likely running under path %s",
            softwareIdentity.getSoftware(), rootPath);
      }
      detectedSoftwareBuilder.add(
          DetectedSoftware.builder()
              .setSoftwareIdentity(softwareIdentity)
              .setRootPath(rootPath)
              .setContentHashes(contentHashes)
              .build());
    }
    return detectedSoftwareBuilder.build();
  }

  private ImmutableSetMultimap<SoftwareIdentity, CrawlResult> matchPotentialSoftware(
      ImmutableMap<CrawlResult, Hash> crawlResultHashes) {
    ImmutableSetMultimap.Builder<SoftwareIdentity, CrawlResult> matchedSoftwareBuilder =
        ImmutableSetMultimap.builder();
    for (CrawlResult crawlResult : crawlResultHashes.keySet()) {
      Hash hash = crawlResultHashes.get(crawlResult);
      // A single content hash could be mapped to multiple potential software, e.g. jQuery can be
      // used by multiple web applications.
      for (SoftwareIdentity matchedSoftware : fingerprintRegistry.matchSoftwareForHash(hash)) {
        matchedSoftwareBuilder.put(matchedSoftware, crawlResult);
      }
    }
    return matchedSoftwareBuilder.build();
  }

  private String findRootPath(
      SoftwareIdentity softwareIdentity, ImmutableMap<CrawlResult, Hash> crawlResultHashes) {
    logger.atInfo().log(
        "Found %d indicators for %s", crawlResultHashes.size(), softwareIdentity.getSoftware());
    Optional<FingerprintData> fingerprintData =
        fingerprintRegistry.getFingerprintData(softwareIdentity);
    if (!fingerprintData.isPresent()) {
      logger.atWarning().log(
          "Fingerprint data for software %s doesn't exist.", softwareIdentity.getSoftware());
      return "";
    }

    HashMultiset<String> rootUrls = HashMultiset.create();
    for (CrawlResult crawlResult : crawlResultHashes.keySet()) {
      // For each crawled URL, if one of the known URLs from the fingerprint data is part of the
      // crawled URL, then the difference between them is the subfolder that serves the crawled
      // content.
      String crawledUrl = crawlResult.getCrawlTarget().getUrl();
      HttpUrl parsedCrawlUrl = HttpUrl.parse(crawledUrl);
      if (parsedCrawlUrl == null) {
        logger.atSevere().log(
            "Crawled URL %s cannot be parsed.", crawlResult.getCrawlTarget().getUrl());
        continue;
      }
      fingerprintData.get().contentHashes().keySet().stream()
          .filter(knownPath -> parsedCrawlUrl.encodedPath().endsWith(knownPath))
          .forEach(
              knownPath -> {
                logger.atInfo().log(
                    "Found known path %s that matches crawled URL %s",
                    knownPath, crawlResult.getCrawlTarget().getUrl());
                String rootUrl = crawledUrl.substring(0, crawledUrl.indexOf(knownPath));
                rootUrls.add(rootUrl);
              });
    }

    logger.atInfo().log(
        "Confirmed %d of %d root path indicators for %s.",
        rootUrls.size(), crawlResultHashes.size(), softwareIdentity.getSoftware());
    if (rootUrls.isEmpty()) {
      return "";
    }

    return determineRootPath(rootUrls);
  }

  private static String determineRootPath(HashMultiset<String> rootUrls) {
    if (rootUrls.isEmpty()) {
      return "";
    }
    // Find the most common path prefix from all collected root URLs.
    List<String> rootPathSegments =
        rootUrls.elementSet().stream()
            .map(url -> Optional.ofNullable(HttpUrl.parse(url)))
            .flatMap(Streams::stream)
            .map(HttpUrl::encodedPathSegments)
            .reduce(
                (commonPrefixSegments, pathSegments) -> {
                  List<String> prefixSegments = Lists.newArrayList();
                  for (int i = 0; i < min(commonPrefixSegments.size(), pathSegments.size()); i++) {
                    if (commonPrefixSegments.get(i).equals(pathSegments.get(i))) {
                      prefixSegments.add(commonPrefixSegments.get(i));
                    } else {
                      break;
                    }
                  }
                  return prefixSegments;
                })
            .orElse(Lists.newArrayList());
    // Ensure sub-path has leading slash.
    if (rootPathSegments.isEmpty() || !rootPathSegments.get(0).isEmpty()) {
      rootPathSegments.add(0, "");
    }
    // Ensure sub-path has trailing slash.
    if (rootPathSegments.size() == 1 || !Iterables.getLast(rootPathSegments).isEmpty()) {
      rootPathSegments.add("");
    }
    return Joiner.on("/").join(rootPathSegments);
  }

  /**
   * Checks if at least one of the crawled web content has hashes that are unique to that software.
   * This is useful to avoid false positives, so that a common library does not trigger a detection.
   * This works better the more software was fingerprinted.
   */
  private boolean hasGloballyUniqueHash(ImmutableMap<CrawlResult, Hash> crawlResultHashes) {
    for (CrawlResult crawlResult : crawlResultHashes.keySet()) {
      Hash hash = crawlResultHashes.get(crawlResult);
      if (fingerprintRegistry.isGloballyUniqueHash(hash)) {
        logger.atInfo().log(
            "Found globally unique content at %s", crawlResult.getCrawlTarget().getUrl());
        return true;
      }
    }
    return false;
  }

  /** The software detection result. */
  @AutoValue
  public abstract static class DetectedSoftware {
    public abstract SoftwareIdentity softwareIdentity();
    // Will be empty if rootPath not identified.
    public abstract String rootPath();
    public abstract ImmutableMap<CrawlResult, Hash> contentHashes();

    public static Builder builder() {
      return new com.google.tsunami.plugins.fingerprinters.web.detection
          .AutoValue_SoftwareDetector_DetectedSoftware.Builder();
    }

    /** Builder for {@link DetectedSoftware}. */
    @AutoValue.Builder
    public abstract static class Builder {
      public abstract Builder setSoftwareIdentity(SoftwareIdentity value);
      public abstract Builder setRootPath(String value);
      public abstract Builder setContentHashes(ImmutableMap<CrawlResult, Hash> value);

      public abstract DetectedSoftware build();
    }
  }
}
