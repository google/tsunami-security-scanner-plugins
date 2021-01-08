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
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.tsunami.common.net.UrlUtils.removeLeadingSlashes;
import static com.google.tsunami.common.net.http.HttpMethod.GET;
import static com.google.tsunami.plugins.fingerprinters.web.common.CrawlUtils.buildCrawlResult;
import static com.google.tsunami.plugins.fingerprinters.web.common.FingerprintUtils.hashCrawlResult;
import static java.util.Comparator.comparing;
import static java.util.stream.Collectors.toCollection;

import com.google.auto.value.AutoValue;
import com.google.common.base.Joiner;
import com.google.common.base.Strings;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Sets;
import com.google.common.flogger.GoogleLogger;
import com.google.inject.assistedinject.Assisted;
import com.google.tsunami.common.net.UrlUtils;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpRequest;
import com.google.tsunami.common.net.http.HttpResponse;
import com.google.tsunami.plugins.fingerprinters.web.data.FingerprintData;
import com.google.tsunami.plugins.fingerprinters.web.data.FingerprintRegistry;
import com.google.tsunami.plugins.fingerprinters.web.detection.SoftwareDetector.DetectedSoftware;
import com.google.tsunami.plugins.fingerprinters.web.proto.ContentHash;
import com.google.tsunami.plugins.fingerprinters.web.proto.Hash;
import com.google.tsunami.plugins.fingerprinters.web.proto.HashVersion;
import com.google.tsunami.plugins.fingerprinters.web.proto.PathVersion;
import com.google.tsunami.plugins.fingerprinters.web.proto.SoftwareIdentity;
import com.google.tsunami.plugins.fingerprinters.web.proto.Version;
import com.google.tsunami.proto.CrawlResult;
import com.google.tsunami.proto.CrawlTarget;
import com.google.tsunami.proto.NetworkService;
import java.io.IOException;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import javax.inject.Inject;
import okhttp3.HttpUrl;

/** Identifies the potential software versions based on the crawled web content hashes. */
public final class VersionDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private final FingerprintRegistry fingerprintRegistry;
  private final HttpClient httpClient;
  private final NetworkService networkService;
  private final FingerprintData fingerprintData;
  private final DetectedSoftware detectedSoftware;
  private final Set<String> crawledFiles;
  private final int maxAllowedFailedRequest;
  private final int maxAllowedHttpRequest;

  @Inject
  VersionDetector(
      FingerprintRegistry fingerprintRegistry,
      HttpClient httpClient,
      @Assisted NetworkService networkService,
      @Assisted FingerprintData fingerprintData,
      @Assisted DetectedSoftware detectedSoftware,
      @Assisted("maxAllowedFailedRequest") int maxAllowedFailedRequest,
      @Assisted("maxAllowedHttpRequest") int maxAllowedHttpRequest) {
    this.fingerprintRegistry = checkNotNull(fingerprintRegistry);
    this.httpClient = checkNotNull(httpClient);
    this.networkService = checkNotNull(networkService);
    this.fingerprintData = checkNotNull(fingerprintData);
    this.detectedSoftware = checkNotNull(detectedSoftware);
    this.maxAllowedFailedRequest = maxAllowedFailedRequest;
    this.maxAllowedHttpRequest = maxAllowedHttpRequest;
    this.crawledFiles =
        detectedSoftware.contentHashes().keySet().stream()
            .map(crawlResult -> crawlResult.getCrawlTarget().getUrl())
            .map(HttpUrl::parse)
            .filter(Objects::nonNull)
            .map(VersionDetector::getPathFromUrl)
            .collect(toCollection(HashSet::new));
  }

  private static String getPathFromUrl(HttpUrl url) {
    String query = url.encodedQuery();
    if (Strings.isNullOrEmpty(query)) {
      return url.encodedPath();
    }
    return url.encodedPath() + "?" + query;
  }

  /**
   * Determine which versions of the {@code detectedSoftware} could be running based on which
   * versions in the fingerprint database the {@code crawledFiles} correspond to.
   */
  public DetectedVersion detectVersions() {
    if (detectedSoftware.contentHashes().isEmpty()) {
      logger.atInfo().log(
          "Cannot determine versions for %s because no crawl results found.",
          detectedSoftware.softwareIdentity().getSoftware());
      return DetectedVersion.newForUnknownVersion(detectedSoftware.softwareIdentity());
    }

    String software = detectedSoftware.softwareIdentity().getSoftware();
    ImmutableSet<Version> possibleVersions = findPossibleVersionsFromFileHashes();
    logger.atInfo().log(
        "Possible versions for software %s from file hashes are: [%s]",
        software, getLoggableVersions(possibleVersions));
    possibleVersions = siftUsingFilePaths(possibleVersions);
    logger.atInfo().log(
        "Possible versions for software %s after file path sifting: [%s]",
        software, getLoggableVersions(possibleVersions));
    possibleVersions = siftUsingUnstableFiles(possibleVersions);
    logger.atInfo().log(
        "Possible versions for software %s after unstable files sifting: [%s]",
        software, getLoggableVersions(possibleVersions));
    return DetectedVersion.builder()
        .setSoftwareIdentity(detectedSoftware.softwareIdentity())
        .setVersions(possibleVersions)
        .build();
  }

  private static String getLoggableVersions(ImmutableSet<Version> versions) {
    return Joiner.on(", ").join(versions.stream().map(Version::getFullName).iterator());
  }

  private ImmutableSet<Version> findPossibleVersionsFromFileHashes() {
    ImmutableList<Hash> fileHashes =
        detectedSoftware.contentHashes().values().stream()
            .filter(this::isKnownHash)
            .filter(hash -> !isPossibleSharedLibrary(hash))
            .collect(toImmutableList());
    return getAllVersionsForHashes(fileHashes).stream()
        .reduce(Sets::intersection)
        .map(ImmutableSet::copyOf)
        .orElse(ImmutableSet.of());
  }

  private boolean isKnownHash(Hash hash) {
    return fingerprintData.hashVersions().containsKey(hash);
  }

  private ImmutableList<Set<Version>> getAllVersionsForHashes(ImmutableList<Hash> fileHashes) {
    return fileHashes.stream().map(hash -> getVersionsForHash(hash)).collect(toImmutableList());
  }

  private ImmutableSet<Version> getVersionsForHash(Hash hash) {
    return ImmutableSet.copyOf(
        fingerprintData
            .hashVersions()
            .getOrDefault(hash, HashVersion.getDefaultInstance())
            .getVersionsList());
  }

  private ImmutableSet<Version> siftUsingFilePaths(ImmutableSet<Version> versions) {
    ImmutableList<String> filePaths =
        crawledFiles.stream()
            .map(UrlUtils::removeLeadingSlashes)
            .filter(this::isKnownPath)
            .filter(path -> !isPossibleSharedLibrary(path))
            .collect(toImmutableList());
    ImmutableSet<Version> pathVersions =
        getAllVersionsForPaths(filePaths).stream()
            .reduce(Sets::intersection)
            .map(ImmutableSet::copyOf)
            .orElse(ImmutableSet.of());

    if (pathVersions.isEmpty()) {
      return versions;
    }
    return Sets.intersection(versions, pathVersions).immutableCopy();
  }

  private boolean isKnownPath(String path) {
    return fingerprintData.pathVersions().containsKey(path);
  }

  private ImmutableList<Set<Version>> getAllVersionsForPaths(ImmutableList<String> filePaths) {
    return filePaths.stream().map(path -> getVersionsForPath(path)).collect(toImmutableList());
  }

  private ImmutableSet<Version> getVersionsForPath(String path) {
    return ImmutableSet.copyOf(
        fingerprintData
            .pathVersions()
            .getOrDefault(path, PathVersion.getDefaultInstance())
            .getVersionsList());
  }

  private boolean isPossibleSharedLibrary(Hash hash) {
    return !fingerprintRegistry.isGloballyUniqueHash(hash);
  }

  private boolean isPossibleSharedLibrary(String path) {
    return !fingerprintRegistry.isGloballyUniquePath(path);
  }

  private ImmutableSet<Version> siftUsingUnstableFiles(ImmutableSet<Version> versions) {
    Iterator<String> unstableFilesItor = getUnstableFiles().iterator();
    Set<Version> siftedVersions = Sets.newHashSet(versions);
    int failedRequestCount = 0;
    int totalRequestCount = 0;

    while (siftedVersions.size() > 1
        && failedRequestCount < maxAllowedFailedRequest
        && totalRequestCount < maxAllowedHttpRequest
        && unstableFilesItor.hasNext()) {
      String unstableFile = unstableFilesItor.next();
      if (crawledFiles.contains(unstableFile)
          || !doesFileNarrowDownVersions(siftedVersions, unstableFile)) {
        continue;
      }

      crawledFiles.add(unstableFile);
      Optional<HttpUrl> unstableFileUrl = buildTargetUrl(unstableFile);
      if (unstableFileUrl.isPresent()) {
        try {
          logger.atInfo().log("VersionDetector requesting file at %s", unstableFileUrl.get());
          Set<Version> versionsForUnstableFile = knownVersionsForFile(unstableFileUrl.get());
          totalRequestCount++;
          if (versionsForUnstableFile.isEmpty()) {
            logger.atInfo().log(
                "Version for file '%s' is unknown, ignored.", unstableFileUrl.get());
          } else {
            siftedVersions.retainAll(versionsForUnstableFile);
          }
        } catch (IOException e) {
          failedRequestCount++;
          logger.atWarning().log("Skip failed request for new target %s.", unstableFileUrl.get());
        }
      }
    }
    return ImmutableSet.copyOf(siftedVersions);
  }

  /**
   * Retrieves a list of "unstable" file based on the updating frequency (# of versions per hash).
   */
  private ImmutableList<String> getUnstableFiles() {
    ImmutableMap<String, ContentHash> contentHashes = fingerprintData.contentHashes();
    return ImmutableList.sortedCopyOf(
        comparing(path -> contentHashes.get(path).getHashesCount()).reversed(),
        contentHashes.keySet());
  }

  /**
   * Crawls a single target URL and determines the potential versions based on the hashes of the
   * crawl result.
   */
  private ImmutableSet<Version> knownVersionsForFile(HttpUrl url) throws IOException {
    HttpResponse response =
        httpClient.send(HttpRequest.get(url).withEmptyHeaders().build(), networkService);
    CrawlResult crawlResult =
        buildCrawlResult(
            CrawlTarget.newBuilder().setUrl(url.toString()).setHttpMethod(GET.toString()).build(),
            0,
            response);
    return getVersionsForHash(hashCrawlResult(crawlResult));
  }

  private boolean doesFileNarrowDownVersions(Set<Version> versions, String file) {
    return fingerprintData.contentHashes().get(file).getHashesList().stream()
        .map(hash -> fingerprintData.hashVersions().get(hash))
        .noneMatch(hashVersion -> hashVersion.getVersionsList().containsAll(versions));
  }

  /** Build the URL for the file to crawl based on the existing crawling result. */
  private Optional<HttpUrl> buildTargetUrl(String file) {
    CrawlResult crawlResult = detectedSoftware.contentHashes().keySet().iterator().next();
    HttpUrl crawledUrl = HttpUrl.parse(crawlResult.getCrawlTarget().getUrl());
    if (crawledUrl == null) {
      return Optional.empty();
    }
    HttpUrl.Builder targetUrlBuilder = crawledUrl.newBuilder().query(null).fragment(null);
    String rootPath = detectedSoftware.rootPath().isEmpty() ? "/" : detectedSoftware.rootPath();
    return Optional.of(
        targetUrlBuilder.encodedPath(rootPath).addPathSegments(removeLeadingSlashes(file)).build());
  }

  /** The factory of {@link VersionDetector} types for usage with assisted injection. */
  public interface Factory {
    VersionDetector create(
        NetworkService networkService,
        FingerprintData fingerprintData,
        DetectedSoftware detectedSoftware,
        @Assisted("maxAllowedFailedRequest") int maxAllowedFailedRequest,
        @Assisted("maxAllowedHttpRequest") int maxAllowedHttpRequest);
  }

  /** The version detection result. */
  @AutoValue
  public abstract static class DetectedVersion {
    public abstract SoftwareIdentity softwareIdentity();
    public abstract ImmutableSet<Version> versions();

    public static DetectedVersion newForUnknownVersion(SoftwareIdentity softwareIdentity) {
      return builder().setSoftwareIdentity(softwareIdentity).setVersions(ImmutableSet.of()).build();
    }

    public static Builder builder() {
      return new com.google.tsunami.plugins.fingerprinters.web.detection
          .AutoValue_VersionDetector_DetectedVersion.Builder();
    }

    /** Builder for {@link DetectedVersion}. */
    @AutoValue.Builder
    abstract static class Builder {
      public abstract Builder setSoftwareIdentity(SoftwareIdentity value);
      public abstract Builder setVersions(Collection<Version> value);

      public abstract DetectedVersion build();
    }
  }
}
