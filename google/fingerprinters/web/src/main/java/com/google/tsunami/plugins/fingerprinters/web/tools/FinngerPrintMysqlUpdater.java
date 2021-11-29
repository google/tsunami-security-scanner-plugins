package com.google.tsunami.plugins.fingerprinters.web.tools;

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
import com.google.tsunami.plugins.fingerprinters.web.common.WebConstant;
import com.google.tsunami.plugins.fingerprinters.web.crawl.Crawler;
import com.google.tsunami.plugins.fingerprinters.web.crawl.ScopeUtils;
import com.google.tsunami.plugins.fingerprinters.web.crawl.SimpleCrawlerModule;
import com.google.tsunami.plugins.fingerprinters.web.proto.*;
import com.google.tsunami.proto.CrawlConfig;
import com.google.tsunami.proto.CrawlResult;
import com.google.tsunami.proto.CrawlTarget;
import com.google.tsunami.proto.NetworkService;
import io.github.classgraph.ClassGraph;
import io.github.classgraph.ScanResult;
import okhttp3.HttpUrl;

import javax.inject.Inject;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.SQLException;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

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

public final class FinngerPrintMysqlUpdater {

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
    private static final ImmutableSet<String> IGNORED_EXTENTIONS = WebConstant.IGNORED_EXTENTIONS;

    private final FinngerPrintMysqlUpdater.Options options;
    private final HttpClient httpClient;
    private final Crawler crawler;
    private final NetworkService fakeNetworkService;

    @Inject
    public FinngerPrintMysqlUpdater(FinngerPrintMysqlUpdater.Options options, HttpClient httpClient, Crawler crawler) {
        this.options = checkNotNull(options);
        this.httpClient = checkNotNull(httpClient);
        this.fakeNetworkService = NetworkService.getDefaultInstance();
        this.crawler = checkNotNull(crawler);
    }

    /**
     * 首先抓取所需的页面，
     *
     */
    public void update() throws IOException, SQLException {
        ImmutableMap<String, Hash> path2hash = new ImmutableMap.Builder<String, Hash>().build();     //.putAll(fileHashes).build();

        ImmutableSetMultimap<String, Hash> hashesByCrawledPath = crawlLiveApp();
        for (String crawledPath : hashesByCrawledPath.keySet()) {
            ImmutableSet<Hash> uniqueHashes = hashesByCrawledPath.get(crawledPath);
            if (uniqueHashes.size() != 1) {
                throw new AssertionError(
                        String.format("Same path %s but different hashes %s.", crawledPath, uniqueHashes));
            }
            path2hash.put(crawledPath, uniqueHashes.iterator().next());
        }
        logger.atInfo().log(
                "Crawler identified %s files. Moving on to check local static files.", path2hash.size());
        // 先根据path去software2path中取出path,然后把path对应的hash作为参数再取path_hash_version;
        MysqlUtil.loadPathHashVersionsByHashs(path2hash.keySet());

        //由于我们知道当前要抓取的软件、软件对应的路径、路径对应的hash和参数传递过来的version。 这样我们就可以进行数据库更新了
        String software = options.softwareName;
        String version = options.version;
        //确定当前库中是否已经有相关软件及版本信息,
        Map<String,Integer> version2cnt = MysqlUtil.getVersionsByPathAndHash(path2hash);
        //确认已经有了
        if(version2cnt.getOrDefault(version,0)>0){
            throw new AssertionError(
                    String.format("发现数据库中已经有相关版本了，版本 %s.",version));
        }else {
           boolean inertSotfwarePath =  MysqlUtil.insertSoftware2Path(software,path2hash.keySet());
           if (inertSotfwarePath) {
               Set<String> sqls = new HashSet<>();
               path2hash.forEach((path,hash) ->{
                   //if ()
                   sqls.add(MysqlUtil.pathHashVersionsInnertSql(path,hash.getHexString(),version));
               });
               boolean insertPathHashVersions = MysqlUtil.innertPathHashVersions(sqls);
           }
        }





    }

    /**
     * 抓取操作
     * @return
     */
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
                        .setNetworkService(fakeNetworkService)
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

    private static boolean isIgnoredCrawledFile(String relativePath) {
        // Use the relative path so that parent directory names are not checked.
        String extension = Files.getFileExtension(Ascii.toLowerCase(relativePath));

        return extension.isEmpty() || IGNORED_EXTENTIONS.contains(extension);
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
        Arrays.stream(args).forEach(System.out::println);
        try (ScanResult scanResult =
                     new ClassGraph()
                             .enableAllInfo()
                             .blacklistPackages("com.google.tsunami.plugin.testing")
                             .scan()) {
            Injector injector =
                    Guice.createInjector(
                            new CliOptionsModule(scanResult, "FingerprintMysqlUpdater", args),
                            new HttpClientModule.Builder().build(),
                            new SimpleCrawlerModule(MAX_CRAWLING_THREAD));
            injector.getInstance(FinngerPrintMysqlUpdater.class).update();
        } catch (Throwable e) {
            logger.atSevere().withCause(e).log("Error updating fingerprint data");
            System.exit(1);
        }
    }

    /** {@code Options} holds parameters for the {@link FingerprintUpdater}. */
    @Parameters(separators = "=")
    public static class Options implements CliOption {
        @Parameter(names = "--software-name", description = "Name of the software.", required = true)
        public String softwareName;

        @Parameter(names = "--plugin-name", description = "(Optional) Name of the software plugin.")
        public String pluginName;

        @Parameter(names = "--version", description = "Version of the software.", required = true)
        public String version;

        @Parameter(
                names = "--init",
                description = "Whether the updater should initialize the fingerprint data.")
        public boolean init = false;

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
