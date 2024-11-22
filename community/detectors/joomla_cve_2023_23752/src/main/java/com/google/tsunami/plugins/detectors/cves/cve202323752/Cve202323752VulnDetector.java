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
package com.google.tsunami.plugins.detectors.cves.cve202323752;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.common.net.HttpHeaders.ACCEPT;
import static com.google.tsunami.common.net.http.HttpRequest.get;

import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonSyntaxException;
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
import com.google.tsunami.proto.AdditionalDetail;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.TextData;
import com.google.tsunami.proto.Vulnerability;
import com.google.tsunami.proto.VulnerabilityId;
import java.io.IOException;
import java.time.Clock;
import java.time.Instant;
import javax.inject.Inject;

/** A {@link VulnDetector} that detects the CVE-2023-23752 vulnerability. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "Cve202323752VulnDetector",
    version = "0.1",
    description =
        "Joomla CVE-2023-23752: An information disclosure allows to retrieve the database credentials",
    author = "Am0o0",
    bootstrapModule = Cve202323752DetectorBootstrapModule.class)
public final class Cve202323752VulnDetector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private final HttpClient httpClient;
  private final Clock utcClock;
  private String exposedConfig;

  @Inject
  Cve202323752VulnDetector(@UtcClock Clock utcClock, HttpClient httpClient) {
    this.httpClient = checkNotNull(httpClient);
    this.utcClock = checkNotNull(utcClock);
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("CVE-2023-23752 starts detecting.");

    return DetectionReportList.newBuilder()
        .addAllDetectionReports(
            matchedServices.stream()
                .filter(this::isServiceVulnerable)
                .map(networkService -> buildDetectionReport(targetInfo, networkService))
                .collect(toImmutableList()))
        .build();
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
                        .setValue("CVE_2023_23752"))
                .setSeverity(Severity.HIGH)
                .setTitle("Joomla unauthorized access to webservice endpoints")
                .setDescription(
                    "CVE-2023-23752: An improper access check allows unauthorized access to"
                        + " webservice endpoints. attacker can get the host address "
                        + "and username and password of the configured joomla database.")
                .setRecommendation("Upgrade Joomla to 4.2.8 and above versions.")
                .addAdditionalDetails(
                    AdditionalDetail.newBuilder()
                        .setTextData(TextData.newBuilder().setText(exposedConfig))))
        .build();
  }

  private boolean isServiceVulnerable(NetworkService networkService) {
    HttpHeaders httpHeaders =
        HttpHeaders.builder()
            .addHeader(
                ACCEPT,
                "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
            .build();

    String appConfUrl =
        NetworkServiceUtils.buildWebApplicationRootUrl(networkService)
            + "api/index.php/v1/config/application?public=true";
    try {
      HttpResponse appConfHttpResponse =
          httpClient.send(get(appConfUrl).setHeaders(httpHeaders).build(), networkService);

      // immediate checks for accelerating the scan
      if (appConfHttpResponse.status().code() != HttpStatus.OK.code()
          || appConfHttpResponse.bodyJson().isEmpty()
          || appConfHttpResponse.bodyString().isEmpty()) {
        return false;
      }

      // check for body values match our detection rules
      if (appConfHttpResponse.bodyString().get().contains("password")
          && appConfHttpResponse.bodyString().get().contains("user")) {

        JsonObject jsonResponse = (JsonObject) appConfHttpResponse.bodyJson().get();
        if (jsonResponse.keySet().contains("data")) {
          JsonArray jsonArray = jsonResponse.getAsJsonArray("data");
          for (int i = 0; i < jsonArray.size(); i++) {
            if (jsonArray.get(i).getAsJsonObject().keySet().contains("attributes")) {
              exposedConfig = appConfHttpResponse.bodyString().get();
              return true;
            }
          }
        }
      }
    } catch (NoSuchElementException | IllegalStateException | JsonSyntaxException e) {
      return false;
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Request to target %s failed", networkService);
      return false;
    }
    return false;
  }
}
