package com.google.tsunami.plugins.detectors.authentication.cve202138540;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.common.net.HttpHeaders.CONTENT_TYPE;
import static com.google.tsunami.common.net.http.HttpRequest.get;
import static com.google.tsunami.common.net.http.HttpRequest.post;

import com.google.common.base.Splitter;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Iterables;
import com.google.common.flogger.GoogleLogger;
import com.google.protobuf.ByteString;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpHeaders;
import com.google.tsunami.common.net.http.HttpResponse;
import com.google.tsunami.common.time.UtcClock;
import com.google.tsunami.plugin.PluginType;
import com.google.tsunami.plugin.VulnDetector;
import com.google.tsunami.plugin.annotations.PluginInfo;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.Vulnerability;
import com.google.tsunami.proto.VulnerabilityId;
import java.io.IOException;
import java.time.Clock;
import java.time.Instant;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.inject.Inject;

/** A {@link VulnDetector} that detects Apache Airflow CVE-2017-7615 vulnerability. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "ApacheAirflowCVE202138540VulnDetector",
    version = "0.1",
    description = "Tsunami detector plugin for Apache Airflow CVE-2021-38540.",
    author = "Sttor (security@sttor.com)",
    bootstrapModule = ApacheAirflowCVE202138540VulnDetectorBootstrapModule.class)
public final class ApacheAirflowCVE202138540VulnDetector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private static final String VULNERABLE_ENDPOINT = "variable/varimport";
  private static final String CSRF_ENDPOINT = "login/";
  private static final String JSON_FILE_PAYLOAD = "{\"tsunami_scanner_var\": \"tsunami_value\"}";
  private static final String VUL_REDIRECT_STR = "<a href=\"/\"";
  private static final Pattern CSRF_TOKEN_PATTERN =
      Pattern.compile(
          "<input id=\"csrf_token\" name=\"csrf_token\" type=\"hidden\" value=\"(.*?)\">");

  private final Clock utcClock;
  private final HttpClient httpClient;

  @Inject
  ApacheAirflowCVE202138540VulnDetector(@UtcClock Clock utcClock, HttpClient httpClient) {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient).modify().setFollowRedirects(false).build();
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("Starting CVE-2021-38540 detection for Apache Airflow.");
    DetectionReportList detectionReports =
        DetectionReportList.newBuilder()
            .addAllDetectionReports(
                matchedServices.stream()
                    .filter(NetworkServiceUtils::isWebService)
                    .filter(this::isServiceVulnerable)
                    .map(networkService -> buildDetectionReport(targetInfo, networkService))
                    .collect(toImmutableList()))
            .build();

    logger.atInfo().log("ApacheAirflowCVE202138540VulnDetector finished.");
    return detectionReports;
  }

  private boolean isServiceVulnerable(NetworkService networkService) {
    String csrfUri = NetworkServiceUtils.buildWebApplicationRootUrl(networkService);
    csrfUri = csrfUri + CSRF_ENDPOINT;
    String targetUri = NetworkServiceUtils.buildWebApplicationRootUrl(networkService);
    targetUri = targetUri + VULNERABLE_ENDPOINT;
    HttpResponse response;
    String csrfToken;

    // Request 1: plain GET request to create a session and retrieve the session cookie and csrf.
    logger.atInfo().log("Getting CSRF token and session from login page '%s'.", csrfUri);
    try {
      response = httpClient.send(get(csrfUri).withEmptyHeaders().build(), networkService);
      csrfToken = getCSRFToken(response);
      logger.atInfo().log("$$$$csrf '%s'", csrfToken);
      if (csrfToken.isEmpty()) {
        return false;
      }
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Exception in fetching CSRF token '%s'.", csrfUri);
      return false;
    }

    ImmutableList<String> cookies = parseCookies(response);
    if (cookies.isEmpty()) {
      logger.atInfo().log("No Set-Cookie header in the HTTP response.");
      return false;
    }

    // Request 2: Http post to unauthenticated varimport endpoint.
    logger.atInfo().log("Sending file payload to target '%s'.", targetUri);
    try {
      response = executeHttpRequestWithPayload(networkService, targetUri, cookies, csrfToken);
      logger.atInfo().log("Sending file payload to target '%s'.", response);
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Unable to query '%s'.", targetUri);
      return false;
    }
    return response.status().code() == 302
        && response.bodyString().map(body -> body.contains(VUL_REDIRECT_STR)).orElse(false);
  }

  private static ImmutableList<String> parseCookies(HttpResponse response) {
    return response.headers().getAll("Set-Cookie").stream()
        .map(headerValue -> Iterables.get(Splitter.on(';').split(headerValue), 0))
        .collect(toImmutableList());
  }

  private static String getCSRFToken(HttpResponse response) {
    String csrfToken = "";
    String responseBody = response.bodyString().get();
    Matcher matcher = CSRF_TOKEN_PATTERN.matcher(responseBody);
    if (matcher.find()) {
      csrfToken = matcher.group(1);
    }
    return csrfToken;
  }

  private HttpResponse executeHttpRequestWithPayload(
      NetworkService networkService,
      String targetUri,
      ImmutableList<String> cookies,
      String csrfToken)
      throws IOException {
    String contentType =
        "multipart/form-data; boundary=---------------------------16087738037200538813789640524";
    String payload =
        "-----------------------------16087738037200538813789640524\r\n"
            + "Content-Disposition: form-data; name=\"csrf_token\"\r\n\r\n"
            + csrfToken
            + "\r\n"
            + "-----------------------------16087738037200538813789640524\r\n"
            + "Content-Disposition: form-data; name=\"file\"; filename=\"tsunami_payload.json\"\r\n"
            + "Content-Type: application/json\r\n\r\n"
            + JSON_FILE_PAYLOAD
            + "\r\n"
            + "-----------------------------16087738037200538813789640524--\r\n";

    HttpHeaders headers =
        HttpHeaders.builder()
            .addHeader("Cookie", String.join("; ", cookies))
            .addHeader(CONTENT_TYPE, contentType)
            .build();
    return httpClient.send(
        post(targetUri)
            .setHeaders(headers)
            .setRequestBody(ByteString.copyFrom(payload, "UTF-8"))
            .build(),
        networkService);
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
                        .setValue("CVE_2021_38540"))
                .setSeverity(Severity.CRITICAL)
                .setTitle(
                    "CVE-2021-38540: Apache Airflow Variable Import endpoint missing auth check")
                .setDescription(
                    "The variable import endpoint was not protected by authentication in Airflow"
                        + " >=2.0.0, <2.1.3.This allowed unauthenticated users to hit that endpoint"
                        + " to add/modify Airflow variables usedin DAGs, potentially resulting in a"
                        + " denial of service, information disclosure or remote codeexecution. This"
                        + " issue affects Apache Airflow >=2.0.0, <2.1.3."))
        .build();
  }
}
