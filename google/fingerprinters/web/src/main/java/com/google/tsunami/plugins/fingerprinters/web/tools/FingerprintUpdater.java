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
package com.google.tsunami.plugins.fingerprinters.web.tools;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableSet.toImmutableSet;
import static com.google.common.collect.ImmutableSetMultimap.toImmutableSetMultimap;
import static com.google.common.collect.Streams.stream;
import static com.google.tsunami.common.net.UrlUtils.removeLeadingSlashes;
import static com.google.tsunami.common.net.http.HttpMethod.GET;
import static com.google.tsunami.common.net.http.HttpRequest.get;
import static com.google.tsunami.plugins.fingerprinters.web.common.CrawlUtils.buildCrawlResult;
import static com.google.tsunami.plugins.fingerprinters.web.common.FingerprintUtils.hashCrawlResult;
import static java.nio.charset.StandardCharsets.UTF_8;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParameterException;
import com.beust.jcommander.Parameters;
import com.google.common.base.Ascii;
import com.google.common.base.Strings;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.ImmutableSetMultimap;
import com.google.common.collect.Maps;
import com.google.common.flogger.GoogleLogger;
import com.google.common.io.Files;
import com.google.common.io.MoreFiles;
import com.google.inject.Guice;
import com.google.inject.Injector;
import com.google.protobuf.util.JsonFormat;
import com.google.tsunami.common.cli.CliOption;
import com.google.tsunami.common.cli.CliOptionsModule;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.common.net.http.HttpResponse;
import com.google.tsunami.common.net.http.HttpStatus;
import com.google.tsunami.plugins.fingerprinters.web.common.FingerprintUtils;
import com.google.tsunami.plugins.fingerprinters.web.crawl.Crawler;
import com.google.tsunami.plugins.fingerprinters.web.crawl.ScopeUtils;
import com.google.tsunami.plugins.fingerprinters.web.crawl.SimpleCrawlerModule;
import com.google.tsunami.plugins.fingerprinters.web.proto.ContentHash;
import com.google.tsunami.plugins.fingerprinters.web.proto.Fingerprints;
import com.google.tsunami.plugins.fingerprinters.web.proto.Hash;
import com.google.tsunami.plugins.fingerprinters.web.proto.HashVersion;
import com.google.tsunami.plugins.fingerprinters.web.proto.PathVersion;
import com.google.tsunami.plugins.fingerprinters.web.proto.SoftwareIdentity;
import com.google.tsunami.plugins.fingerprinters.web.proto.Version;
import com.google.tsunami.proto.CrawlConfig;
import com.google.tsunami.proto.CrawlResult;
import com.google.tsunami.proto.CrawlTarget;
import com.google.tsunami.proto.NetworkEndpoint;
import com.google.tsunami.proto.NetworkService;
import io.github.classgraph.ClassGraph;
import io.github.classgraph.ScanResult;
import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.inject.Inject;
import okhttp3.HttpUrl;

/** An updater that updates the fingerprint data for a given software and version. */
public final class FingerprintUpdater {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  private static final int MAX_CRAWLING_THREAD = 4;

  // Ugly stuff...
  // Some application might add random session identifiers to its static contents. We ignore these
  // while building the fingerprint.
  private static final ImmutableSet<Pattern> IGNORED_PATH_PREFIX_PATTERNS =
      ImmutableSet.of(
          // Jenkins static session identifier.
          Pattern.compile("(?:static|adjuncts)/\\w{8}/(.*)"));

  // Files with one of these extensions are not useful for static fingerprinting.
  private static final ImmutableSet<String> IGNORED_EXTENTIONS =
      ImmutableSet.of(
          "php", "inc", "py", "rb", "pl", "java", "lua", "go", "asp", "aspx", "jsp", "cgi", "sql");

  // Folders with one of these names are unlikely to be served to visitors.
  private static final ImmutableSet<String> IGNORED_FOLDERS =
      ImmutableSet.of("build/", "test/", "tests/", "tmp/");

  private final Options options;
  private final HttpClient httpClient;
  private final Crawler crawler;

  @Inject
  public FingerprintUpdater(Options options, HttpClient httpClient, Crawler crawler) {
    this.options = checkNotNull(options);
    this.httpClient = checkNotNull(httpClient);
    this.crawler = checkNotNull(crawler);
  }

  /**
   * The updater performs the following tasks to update the fingerprint data for a given software:
   *
   * <ol>
   *   <li>The updater tries to crawl a live instance of the given software and identify interesting
   *       static files. Hashes are calculated for these files.
   *   <li>If present, the updater tries to identify potential static files from a local code
   *       repository. For each potential static file, the updater tries to query it on the live
   *       instance. If the static file is present, then hashes are calculated.
   *   <li>All the paths to the previously identified static files and their content hashes are
   *       added to the fingerprint database.
   * </ol>
   */
  public void update() throws IOException {
    Fingerprints oldFingerprints = loadFingerprints();
    Map<String, Hash> fileHashes = Maps.newHashMap();

    ImmutableSetMultimap<String, Hash> hashesByCrawledPath = crawlLiveApp();
    for (String crawledPath : hashesByCrawledPath.keySet()) {
      ImmutableSet<Hash> uniqueHashes = hashesByCrawledPath.get(crawledPath);
      if (uniqueHashes.size() != 1) {
        throw new AssertionError(
            String.format("Same path %s but different hashes %s.", crawledPath, uniqueHashes));
      }
      fileHashes.put(crawledPath, uniqueHashes.iterator().next());
    }

    logger.atInfo().log(
        "Crawler identified %s files. Moving on to check local static files.", fileHashes.size());
    fileHashes.putAll(checkLocalRepos(ImmutableSet.copyOf(fileHashes.keySet()), oldFingerprints));
    // Remove empty path if present, this is not useful for fingerprint detection.
    fileHashes.remove("");

    if (fileHashes.isEmpty()) {
      logger.atInfo().log("No new fingerprints found.");
    } else {
      logger.atInfo().log("# of new content hashes = %d", fileHashes.size());
      dumpToFile(updateFingerprints(fileHashes, oldFingerprints));
    }
  }

  private Fingerprints loadFingerprints() throws IOException {
    if (options.init) {
      return Fingerprints.getDefaultInstance();
    }
    return Files.getFileExtension(options.fingerprintDataPath).equals("json")
        ? loadFingerprintsFromJson()
        : loadFingerprintsFromBinProto();
  }

  private Fingerprints loadFingerprintsFromJson() throws IOException {
    Fingerprints.Builder fingerprintsBuilder = Fingerprints.newBuilder();
    JsonFormat.parser()
        .merge(
            Files.asCharSource(Paths.get(options.fingerprintDataPath).toFile(), UTF_8).read(),
            fingerprintsBuilder);
    return fingerprintsBuilder.build();
  }

  private Fingerprints loadFingerprintsFromBinProto() throws IOException {
    return Fingerprints.parseFrom(
        Files.asByteSource(Paths.get(options.fingerprintDataPath).toFile()).openBufferedStream());
  }

  private ImmutableSetMultimap<String, Hash> crawlLiveApp() {
    ImmutableSet<String> seedingUrls =
        options.crawlSeedPaths.isEmpty()
            ? ImmutableSet.of(options.remoteUrl)
            : options.crawlSeedPaths.stream()
                .map(seedPath -> HttpUrl.get(options.remoteUrl).newBuilder().encodedPath(seedPath))
                .map(urlBuilder -> urlBuilder.build().toString())
                .collect(toImmutableSet());
    CrawlConfig crawlConfig =
        CrawlConfig.newBuilder()
            .addAllSeedingUrls(seedingUrls)
            .setMaxDepth(options.maxCrawlDepth)
            .addScopes(ScopeUtils.fromUrl(options.remoteUrl))
            .setNetworkEndpoint(NetworkEndpoint.getDefaultInstance())
            .build();
    return crawler.crawl(crawlConfig).stream()
        .filter(crawlResult -> HttpStatus.fromCode(crawlResult.getResponseCode()).isSuccess())
        .filter(crawlResult -> !isIgnoredCrawledFile(getPathFromCrawlResult(crawlResult)))
        .collect(
            toImmutableSetMultimap(
                crawlResult ->
                    removeIgnoredPrefix(removeLeadingSlashes(getPathFromCrawlResult(crawlResult))),
                FingerprintUtils::hashCrawlResult));
  }

  private static String getPathFromCrawlResult(CrawlResult crawlResult) {
    HttpUrl url = HttpUrl.get(crawlResult.getCrawlTarget().getUrl());
    String query = url.encodedQuery();
    if (Strings.isNullOrEmpty(query)) {
      return url.encodedPath();
    }
    return url.encodedPath() + "?" + query;
  }

  private ImmutableMap<String, Hash> checkLocalRepos(
      ImmutableSet<String> visitedFiles, Fingerprints existingFingerprints) {
    ImmutableMap.Builder<String, Hash> fileHashesBuilder = ImmutableMap.builder();
    ImmutableSet<String> localStaticFiles =
        ImmutableSet.<String>builder()
            .addAll(allLocalStaticFiles())
            // Include all previously known paths as well.
            .addAll(
                existingFingerprints.getContentHashesList().stream()
                    .map(ContentHash::getContentPath)
                    .collect(toImmutableSet()))
            .addAll(
                existingFingerprints.getPathVersionsList().stream()
                    .map(PathVersion::getContentPath)
                    .collect(toImmutableSet()))
            .build();
    for (String staticFile : localStaticFiles) {
      if (visitedFiles.contains(staticFile)) {
        logger.atInfo().log("(Ignore) File %s has already been crawled by crawler.", staticFile);
        continue;
      }

      Optional<Hash> hash = getFileHash(staticFile);
      if (!hash.isPresent()) {
        logger.atInfo().log("(Ignore) No hashes for file %s.", staticFile);
        continue;
      }

      logger.atInfo().log("Get hash %s for file %s", hash.get().getHexString(), staticFile);
      fileHashesBuilder.put(staticFile, hash.get());
    }
    return fileHashesBuilder.build();
  }

  private Optional<Hash> getFileHash(String staticFile) {
    try {
      HttpUrl url =
          HttpUrl.parse(options.remoteUrl).newBuilder().addPathSegments(staticFile).build();
      HttpResponse response =
          httpClient.send(get(url).withEmptyHeaders().build(), NetworkService.getDefaultInstance());
      if (!response.status().isSuccess()) {
        logger.atWarning().log("(Ignored) status %s for file '%s'", response.status(), staticFile);
        return Optional.empty();
      }
      CrawlTarget fakeCrawlTarget =
          CrawlTarget.newBuilder().setUrl(url.toString()).setHttpMethod(GET.toString()).build();
      CrawlResult crawlResult = buildCrawlResult(fakeCrawlTarget, 0, response);
      return Optional.of(hashCrawlResult(crawlResult));
    } catch (IOException e) {
      logger.atWarning().log("(Ignored) Error request file '%s'.", staticFile);
      return Optional.empty();
    }
  }

  private ImmutableSet<String> allLocalStaticFiles() {
    if (Strings.isNullOrEmpty(options.localRepoPath)) {
      return ImmutableSet.of();
    }
    Path repoPath = Paths.get(options.localRepoPath);
    return stream(MoreFiles.fileTraverser().depthFirstPreOrder(repoPath))
        .filter(java.nio.file.Files::isRegularFile)
        .map(repoPath::relativize)
        .map(Path::toString)
        .filter(path -> !isIgnoredLocalFile(path))
        .collect(toImmutableSet());
  }

  private static boolean isIgnoredCrawledFile(String relativePath) {
    // Use the relative path so that parent directory names are not checked.
    String extension = Files.getFileExtension(Ascii.toLowerCase(relativePath));

    return extension.isEmpty() || IGNORED_EXTENTIONS.contains(extension);
  }

  private static boolean isIgnoredLocalFile(String relativePath) {
    // Use the relative path so that parent directory names are not checked.
    String extension = Files.getFileExtension(Ascii.toLowerCase(relativePath));

    // Ignores hidden files and folders.
    if (relativePath.startsWith(".") || relativePath.contains("/.")) {
      return true;
    }
    if (IGNORED_EXTENTIONS.contains(extension)) {
      return true;
    }
    return IGNORED_FOLDERS.stream().anyMatch(relativePath::contains);
  }

  private Fingerprints updateFingerprints(
      Map<String, Hash> fileHashes, Fingerprints existingFingerprints) {
    SoftwareIdentity.Builder softwareIdentityBuilder =
        SoftwareIdentity.newBuilder().setSoftware(options.softwareName);
    if (options.pluginName != null) {
      softwareIdentityBuilder.setPlugin(options.pluginName);
    }
    SoftwareIdentity newSoftwareIdentity = softwareIdentityBuilder.build();
    if (!options.init && !newSoftwareIdentity.equals(existingFingerprints.getSoftwareIdentity())) {
      throw new AssertionError("Target software is different from existing fingerprint!");
    }

    Map<String, ContentHash> newContentHashes =
        Maps.newHashMap(
            Maps.uniqueIndex(
                existingFingerprints.getContentHashesList(), ContentHash::getContentPath));
    Map<Hash, HashVersion> newHashVersions =
        Maps.newHashMap(
            Maps.uniqueIndex(existingFingerprints.getHashVersionsList(), HashVersion::getHash));
    Map<String, PathVersion> newPathVersions =
        Maps.newHashMap(
            Maps.uniqueIndex(
                existingFingerprints.getPathVersionsList(), PathVersion::getContentPath));
    for (String filePath : fileHashes.keySet()) {
      Hash fileHash = fileHashes.get(filePath);

      // Update content to hash mapping.
      newContentHashes.putIfAbsent(filePath, ContentHash.getDefaultInstance());
      newContentHashes.compute(
          filePath,
          (path, oldContentHash) ->
              ContentHash.newBuilder()
                  .setContentPath(path)
                  .addAllHashes(
                      ImmutableSet.<Hash>builder()
                          .addAll(oldContentHash.getHashesList())
                          .add(fileHash)
                          .build())
                  .build());

      // Update hash to version mapping.
      newHashVersions.putIfAbsent(fileHash, HashVersion.getDefaultInstance());
      newHashVersions.compute(
          fileHash,
          (hash, oldHashVersion) ->
              HashVersion.newBuilder()
                  .setHash(hash)
                  .addAllVersions(
                      ImmutableSet.<Version>builder()
                          .addAll(oldHashVersion.getVersionsList())
                          .add(Version.newBuilder().setFullName(options.version).build())
                          .build())
                  .build());

      // Update path to version mapping.
      newPathVersions.putIfAbsent(filePath, PathVersion.getDefaultInstance());
      newPathVersions.compute(
          filePath,
          (path, oldPathVersion) ->
              PathVersion.newBuilder()
                  .setContentPath(path)
                  .addAllVersions(
                      ImmutableSet.<Version>builder()
                          .addAll(oldPathVersion.getVersionsList())
                          .add(Version.newBuilder().setFullName(options.version).build())
                          .build())
                  .build());
    }

    return Fingerprints.newBuilder()
        .setSoftwareIdentity(newSoftwareIdentity)
        .addAllContentHashes(newContentHashes.values())
        .addAllHashVersions(newHashVersions.values())
        .addAllPathVersions(newPathVersions.values())
        .build();
  }

  private void dumpToFile(Fingerprints data) throws IOException {
    Path resultPath = buildResultFilePath();
    logger.atInfo().log("Write data file to %s.", resultPath);
    // No-op if the file already exists.
    File resultFile = new File(resultPath.toString());
    Files.createParentDirs(resultFile);
    if (Files.getFileExtension(resultPath.toString()).equals("json")) {
      Files.asCharSink(resultPath.toFile(), UTF_8).write(JsonFormat.printer().print(data));
    } else {
      Files.asByteSink(resultPath.toFile()).write(data.toByteArray());
    }
  }

  private Path buildResultFilePath() {
    Path path = Paths.get(options.fingerprintDataPath);
    if (options.init || options.overrideData) {
      return path;
    }

    String fileName = Files.getNameWithoutExtension(options.fingerprintDataPath);
    String extension = Files.getFileExtension(options.fingerprintDataPath);
    return path.resolveSibling(String.format("%s.%s.%s", fileName, options.version, extension));
  }

  private static String removeIgnoredPrefix(String path) {
    for (Pattern ignoredPrefixPattern : IGNORED_PATH_PREFIX_PATTERNS) {
      Matcher matcher = ignoredPrefixPattern.matcher(path);
      if (matcher.matches()) {
        return matcher.group(1);
      }
    }
    return path;
  }

  public static void main(String[] args) {
    try (ScanResult scanResult =
        new ClassGraph()
            .enableAllInfo()
            .blacklistPackages("com.google.tsunami.plugin.testing")
            .scan()) {
      Injector injector =
          Guice.createInjector(
              new CliOptionsModule(scanResult, "FingerprintUpdater", args),
              new HttpClientModule.Builder().build(),
              new SimpleCrawlerModule(MAX_CRAWLING_THREAD));
      injector.getInstance(FingerprintUpdater.class).update();
    } catch (Throwable e) {
      logger.atSevere().withCause(e).log("Error updating fingerprint data");
      System.exit(1);
    }
  }

  /** {@code Options} holds parameters for the {@link FingerprintUpdater}. */
  @Parameters(separators = "=")
  public static class Options implements CliOption {
    @Parameter(
        names = "--fingerprint-data-path",
        description = "The path to the current fingerprint data.",
        required = true)
    public String fingerprintDataPath;

    @Parameter(
        names = "--override-data",
        description =
            "Whether the existing fingerprint data should be overridden with the updated data. If"
                + " not, this tool generates a new file with the name of"
                + " old-file-name.version.old-file-extension")
    public boolean overrideData = false;

    @Parameter(
        names = "--init",
        description = "Whether the updater should initialize the fingerprint data.")
    public boolean init = false;

    @Parameter(names = "--software-name", description = "Name of the software.", required = true)
    public String softwareName;

    @Parameter(names = "--plugin-name", description = "(Optional) Name of the software plugin.")
    public String pluginName;

    @Parameter(names = "--version", description = "Version of the software.", required = true)
    public String version;

    @Parameter(
        names = "--local-repo-path",
        description = "The path to the local source code repository for the target software.",
        required = true)
    public String localRepoPath;

    @Parameter(
        names = "--remote-url",
        description = "The url to the remote software application instance.",
        required = true)
    public String remoteUrl;

    @Parameter(names = "--crawl-seed-path", description = "The additional path seeds for crawler.")
    public List<String> crawlSeedPaths = new ArrayList<>();

    @Parameter(names = "--max-crawl-depth", description = "The maximum crawling depth.")
    public int maxCrawlDepth = 3;

    @Override
    public void validate() {
      if (HttpUrl.parse(remoteUrl) == null) {
        throw new ParameterException(String.format("Url '%s' is not valid.", remoteUrl));
      }
    }
  }
}
