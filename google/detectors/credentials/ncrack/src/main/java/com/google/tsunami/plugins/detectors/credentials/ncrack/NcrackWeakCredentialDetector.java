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
package com.google.tsunami.plugins.detectors.credentials.ncrack;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.tsunami.common.net.http.HttpRequest.get;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Ascii;
import com.google.common.base.Stopwatch;
import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpResponse;
import com.google.tsunami.common.time.UtcClock;
import com.google.tsunami.plugin.PluginType;
import com.google.tsunami.plugin.VulnDetector;
import com.google.tsunami.plugin.annotations.PluginInfo;
import com.google.tsunami.plugins.detectors.credentials.ncrack.composer.WeakCredentialComposer;
import com.google.tsunami.plugins.detectors.credentials.ncrack.provider.CredentialProvider;
import com.google.tsunami.plugins.detectors.credentials.ncrack.provider.TestCredential;
import com.google.tsunami.plugins.detectors.credentials.ncrack.provider.Top100Passwords;
import com.google.tsunami.plugins.detectors.credentials.ncrack.tester.CredentialTester;
import com.google.tsunami.proto.AdditionalDetail;
import com.google.tsunami.proto.Credential;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.Software;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.Vulnerability;
import com.google.tsunami.proto.VulnerabilityId;
import java.io.IOException;
import java.time.Clock;
import java.time.Instant;
import javax.inject.Inject;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

/**
 * The weak credentials plugins checks for the top 100 passwords on all the services supported by
 * {@link NcrackCredentialTester}. See {@link Top100Passwords} for the list of passwords checked by
 * the plugin.
 */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "NcrackWeakCredentialDetectorPlugin",
    version = "0.1",
    description = "Checks for weak credentials using ncrack (https://nmap.org/ncrack/).",
    author = "Tsunami Team (tsunami-dev@google.com)",
    bootstrapModule = NcrackWeakCredentialDetectorBootstrapModule.class)
public final class NcrackWeakCredentialDetector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  private static final Severity DEFAULT_SEVERITY = Severity.CRITICAL;

  private final CredentialProvider provider;
  private final ImmutableList<CredentialTester> testers;
  private final Clock utcClock;
  private final HttpClient httpClient;

  @Inject
  public NcrackWeakCredentialDetector(
      CredentialProvider provider,
      CredentialTester tester,
      @UtcClock Clock utcClock,
      HttpClient httpClient) {
    this(provider, ImmutableList.of(checkNotNull(tester)), utcClock, httpClient);
  }

  @VisibleForTesting
  NcrackWeakCredentialDetector(
      CredentialProvider provider,
      ImmutableList<CredentialTester> testers,
      Clock utcClock,
      HttpClient httpClient) {
    this.provider = checkNotNull(provider);
    this.testers = checkNotNull(testers);
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient);
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("Starting weak credential detection using ncrack.");
    Stopwatch stopwatch = Stopwatch.createStarted();
    DetectionReportList.Builder detectionReportsBuilder = DetectionReportList.newBuilder();

    doSimpleWebServiceDetection(matchedServices).stream()
        .filter(
            networkService -> testers.stream().anyMatch(tester -> tester.canAccept(networkService)))
        .forEach(
            networkService ->
                testServiceAndAddDetectionReport(
                    targetInfo, networkService, detectionReportsBuilder));
    logger.atInfo().log("Ncrack weak credential detection finished in %s.", stopwatch.stop());
    return detectionReportsBuilder.build();
  }

  private void testServiceAndAddDetectionReport(
      TargetInfo targetInfo,
      NetworkService networkService,
      DetectionReportList.Builder detectionReportsBuilder) {
    testers.stream()
        .filter(tester -> tester.canAccept(networkService))
        .forEach(
            tester ->
                runTesterAndAddFinding(
                    targetInfo, networkService, tester, detectionReportsBuilder));
  }

  private void runTesterAndAddFinding(
      TargetInfo targetInfo,
      NetworkService networkService,
      CredentialTester tester,
      DetectionReportList.Builder detectionReportsBuilder) {
    logger.atInfo().log(
        "Running tester '%s' and credential provider '%s' on service %s.",
        tester.name(), provider.name(), formatNetworkService(networkService));
    ImmutableList<TestCredential> validCredentials =
        new WeakCredentialComposer(provider, tester).run(networkService);
    validCredentials.forEach(
        testCredential ->
            addFindingForCredential(
                targetInfo, networkService, testCredential, detectionReportsBuilder));
  }

  private void addFindingForCredential(
      TargetInfo targetInfo,
      NetworkService networkService,
      TestCredential testCredential,
      DetectionReportList.Builder detectionReportsBuilder) {
    detectionReportsBuilder.addDetectionReports(
        DetectionReport.newBuilder()
            .setTargetInfo(targetInfo)
            .setNetworkService(networkService)
            .setDetectionTimestamp(Timestamps.fromMillis(Instant.now(utcClock).toEpochMilli()))
            .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
            .setVulnerability(
                Vulnerability.newBuilder()
                    .setMainId(
                        VulnerabilityId.newBuilder()
                            .setPublisher("GOOGLE")
                            .setValue(buildVulnerabilityId(networkService)))
                    .setSeverity(DEFAULT_SEVERITY)
                    .setTitle(buildTitle(networkService))
                    .setCvssV3("7.5") // CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
                    .setDescription(buildDescription(networkService))
                    .addAdditionalDetails(buildCredentialDetail(testCredential)))
            .build());
  }

  private static String buildVulnerabilityId(NetworkService networkService) {
    return "WEAK_CREDENTIALS_FOR_"
        + Ascii.toUpperCase(NetworkServiceUtils.getServiceName(networkService));
  }

  private static String buildTitle(NetworkService networkService) {
    return String.format(
        "Weak '%s' service credential", NetworkServiceUtils.getServiceName(networkService));
  }

  private static String buildDescription(NetworkService networkService) {
    String affectedService = NetworkServiceUtils.getServiceName(networkService);
    String affectedPort =
        networkService.getNetworkEndpoint().hasPort()
            ? String.valueOf(networkService.getNetworkEndpoint().getPort().getPortNumber())
            : "unknown";
    return String.format(
        "Well known or weak credentials are detected for '%s' service on port '%s'.",
        affectedService, affectedPort);
  }

  static String formatNetworkService(NetworkService networkService) {
    return String.format(
        "%s (%s, port %d)",
        NetworkServiceUtils.getServiceName(networkService),
        networkService.getTransportProtocol(),
        networkService.getNetworkEndpoint().getPort().getPortNumber());
  }

  private static AdditionalDetail buildCredentialDetail(TestCredential testCredential) {
    Credential.Builder credentialBuilder =
        Credential.newBuilder().setUsername(testCredential.username());
    testCredential.password().ifPresent(credentialBuilder::setPassword);

    return AdditionalDetail.newBuilder()
        .setDescription("Identified credential")
        .setCredential(credentialBuilder)
        .build();
  }

  // TODO(b/154006875): this is a temporary hack as the web fingerprinter is WIP.
  private ImmutableList<NetworkService> doSimpleWebServiceDetection(
      ImmutableList<NetworkService> networkServices) {
    return networkServices.stream()
        .map(
            networkService ->
                NetworkServiceUtils.isWebService(networkService)
                    ? detectSoftware(networkService)
                    : networkService)
        .collect(toImmutableList());
  }

  // TODO(b/154006875): maybe add service detection for other supported web services like Joomla and
  // OWA.
  private NetworkService detectSoftware(NetworkService networkService) {
    if (isWordPressService(networkService)) {
      return NetworkService.newBuilder(networkService)
          .setSoftware(Software.newBuilder().setName("WordPress"))
          .build();
    } else {
      return networkService;
    }
  }

  private boolean isWordPressService(NetworkService networkService) {
    String wordPressLoginUrl =
        NetworkServiceUtils.buildWebApplicationRootUrl(networkService) + "wp-login.php";
    try {
      // This is a blocking call.
      HttpResponse response =
          httpClient.send(get(wordPressLoginUrl).withEmptyHeaders().build(), networkService);
      return response.status().isSuccess()
          && response
              .bodyString()
              .map(
                  body ->
                      // WordPress login page always has a login header pointing to homepage.
                      body.contains("https://wordpress.org/")
                          // Make sure the endpoint serves the login form exploitable by ncrack.
                          && responseHasWordPressLoginForm(body))
              .orElse(false);
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Unable to query '%s'.", wordPressLoginUrl);
      return false;
    }
  }

  private static boolean responseHasWordPressLoginForm(String body) {
    // NCrack detects WordPress credentials by faking this form.
    Elements loginForms = Jsoup.parse(body).select("form#loginform");
    if (loginForms.isEmpty()) {
      return false;
    }

    Element loginForm = loginForms.first();
    return Ascii.equalsIgnoreCase(loginForm.attr("method"), "post")
        && Ascii.toLowerCase(loginForm.attr("action")).contains("wp-login.php");
  }
}
