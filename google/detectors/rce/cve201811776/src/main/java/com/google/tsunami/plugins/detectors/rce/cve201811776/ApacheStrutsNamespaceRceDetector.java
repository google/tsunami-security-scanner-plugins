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
package com.google.tsunami.plugins.detectors.rce.cve201811776;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.common.net.HttpHeaders.LOCATION;
import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpRequest;
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
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.time.Clock;
import java.time.Instant;
import java.util.Objects;
import javax.inject.Inject;

/**
 * A {@link VulnDetector} that detects Apache Struts Command Injection via Namespace
 * (CVE-2018-11776).
 *
 * <p>A vulnerable server will use an invalid namespace as an ONGL expression which is able to
 * execute system commands under the privileges of the web server. We test it by adding an ONGL
 * expression in the namespace. If the evaluated namespace is returned back in the namespace of the
 * redirect url or the error page, then we know our code was executed.
 */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "ApacheStrutsNamespaceRceDetector",
    version = "0.1",
    description =
        "Tsunami detector plugin for Apache Struts Command Injection in namespace "
            + "(CVE-2018-11776).",
    author = "Kumar Ashish (ashishin@google.com)",
    bootstrapModule = ApacheStrutsNamespaceRceDetectorBootstrapModule.class)
public final class ApacheStrutsNamespaceRceDetector implements VulnDetector {

  static final String DETECTOR_HEADER_NAME = "ApacheStrutsNamespaceDetector";
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  private static final String PAYLOAD_STRING = "${'tsunami-' + 'detected-' + 'cve20181776-eipnop'}";
  private static final String INJECTED_STRING = "tsunami-detected-cve20181776-eipnop";
  private static final ImmutableList<String> DEFAULT_APACHE_STRUT_ACTIONS =
      ImmutableList.of(
          "help",
          "about",
          "login",
          "logout",
          "success",
          "failure",
          "createAccount",
          "index",
          "Help",
          "About",
          "Login",
          "Logout",
          "Success",
          "Failure",
          "CreateAccount",
          "Index");

  private final String payloadEncoded;
  private final Clock utcClock;
  private final HttpClient httpClient;

  @Inject
  ApacheStrutsNamespaceRceDetector(@UtcClock Clock utcClock, HttpClient httpClient)
      throws UnsupportedEncodingException {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient).modify().setFollowRedirects(false).build();
    this.payloadEncoded = URLEncoder.encode(PAYLOAD_STRING, UTF_8.toString());
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log(
        "Starting Remote Command Injection via Namespace (CVE-2018-11776) detection for Apache"
            + " Struts.");
    DetectionReportList detectionReports =
        DetectionReportList.newBuilder()
            .addAllDetectionReports(
                matchedServices.stream()
                    .filter(NetworkServiceUtils::isWebService)
                    .filter(this::isServiceVulnerable)
                    .map(networkService -> buildDetectionReport(targetInfo, networkService))
                    .collect(toImmutableList()))
            .build();

    logger.atInfo().log(
        "ApacheStrutsContentTypeRceDetector finished, detected '%d' vulns.",
        detectionReports.getDetectionReportsCount());
    return detectionReports;
  }

  private boolean isServiceVulnerable(NetworkService networkService) {
    String rootUri = NetworkServiceUtils.buildWebApplicationRootUrl(networkService);
    return DEFAULT_APACHE_STRUT_ACTIONS.stream()
        .anyMatch(action -> isActionVulnerable(networkService, rootUri, action));
  }

  private boolean isActionVulnerable(NetworkService networkService, String rootUri, String action) {
    String targetUri = String.format("%s%s/%s", rootUri, payloadEncoded, action);
    HttpResponse httpResponse;
    try {
      httpResponse =
          httpClient.send(HttpRequest.post(targetUri).withEmptyHeaders().build(), networkService);
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Unable to send request at %s", targetUri);
      return false;
    }
    if (httpResponse.status().isRedirect()) {
      if (httpResponse.headers().getAll(LOCATION).stream()
          .filter(Objects::nonNull)
          .anyMatch(redirectLocation -> redirectLocation.contains(INJECTED_STRING))) {
        return true;
      }
    }
    return httpResponse.bodyString().orElse("").contains(INJECTED_STRING);
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
                    VulnerabilityId.newBuilder().setPublisher("GOOGLE").setValue("CVE_2018_11776"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("Apache Struts Command Injection via Namespace (CVE-2018-11776)")
                .setDescription(
                    "Apache Struts versions 2.3 to 2.3.34 and 2.5 to 2.5.16 suffer from possible"
                        + " Remote Code Execution when alwaysSelectFullNamespace is true (either"
                        + " by user or a plugin like Convention Plugin) and then: results are used"
                        + " with no namespace and in same time, its upper package have no or"
                        + " wildcard namespace and similar to results, same possibility when using"
                        + " url tag which doesn't have value and action set and in same time, its"
                        + " upper package have no or wildcard namespace."))
        .build();
  }
}
