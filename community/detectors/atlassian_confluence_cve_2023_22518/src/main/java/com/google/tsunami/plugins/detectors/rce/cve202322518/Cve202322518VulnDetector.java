/*
 * Copyright 2023 Google LLC
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
package com.google.tsunami.plugins.detectors.rce.cve202322518;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.common.net.HttpHeaders.CONTENT_TYPE;
import static com.google.tsunami.common.data.NetworkEndpointUtils.toUriAuthority;
import static com.google.tsunami.common.data.NetworkServiceUtils.buildWebApplicationRootUrl;
import static com.google.tsunami.common.net.http.HttpRequest.post;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.protobuf.ByteString;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpHeaders;
import com.google.tsunami.common.net.http.HttpResponse;
import com.google.tsunami.common.net.http.HttpStatus;
import com.google.tsunami.common.time.UtcClock;
import com.google.tsunami.plugin.PluginType;
import com.google.tsunami.plugin.VulnDetector;
import com.google.tsunami.plugin.annotations.ForWebService;
import com.google.tsunami.plugin.annotations.PluginInfo;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.Vulnerability;
import com.google.tsunami.proto.VulnerabilityId;
import java.time.Clock;
import java.time.Instant;
import java.util.Objects;
import javax.inject.Inject;
import okhttp3.MediaType;
import okhttp3.MultipartBody;
import okhttp3.RequestBody;
import okio.Buffer;

/** A {@link VulnDetector} that detects the CVE-2023-22518 vulnerability. */
@ForWebService
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "Cve202322518VulnDetector",
    version = "0.1",
    description =
        "This detector checks CVE-2023-22518 Atlassian Confluence Data Center Improper"
            + " Authorization",
    author = "amammad",
    bootstrapModule = Cve202322518VulnDetectorBootstrapModule.class)
public class Cve202322518VulnDetector implements VulnDetector {

  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  @VisibleForTesting static final String FILE_UPLOAD_PATH = "json/setup-restore.action";
  @VisibleForTesting static final String RANDOM_ZIP_FILE_NAME = "fiw7rai5kp9ue42r";

  @VisibleForTesting
  static final String RANDOM_ZIP_FILE_CONTENT = "fi1242fsd3w7rfd2sf2ai5kfs2d4p9ue4fd2sf2r";

  private final HttpClient httpClient;
  private final Clock utcClock;

  @Inject
  Cve202322518VulnDetector(HttpClient httpClient, @UtcClock Clock utcClock) {
    this.httpClient = checkNotNull(httpClient);
    this.utcClock = checkNotNull(utcClock);
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("Cve202322518VulnDetector starts detecting.");

    return DetectionReportList.newBuilder()
        .addAllDetectionReports(
            matchedServices.stream()
                .filter(this::isServiceVulnerable)
                .map(networkService -> buildDetectionReport(targetInfo, networkService))
                .collect(toImmutableList()))
        .build();
  }

  @VisibleForTesting
  String buildRootUri(NetworkService networkService) {
    return buildWebApplicationRootUrl(networkService);
  }

  private boolean isServiceVulnerable(NetworkService networkService) {
    final String rootUri = buildRootUri(networkService);
    final String targetUploadUri = rootUri + FILE_UPLOAD_PATH;

    try {
      MultipartBody mBody =
          new MultipartBody.Builder()
              .setType(MultipartBody.FORM)
              .addFormDataPart("buildIndex", "false")
              .addFormDataPart(
                  "file",
                  RANDOM_ZIP_FILE_NAME + ".zip",
                  RequestBody.create(MediaType.parse("application/zip"), RANDOM_ZIP_FILE_CONTENT))
              .addFormDataPart("edit", "Upload and import")
              .build();

      Buffer sink = new Buffer();
      mBody.writeTo(sink);

      HttpResponse response =
          httpClient.send(
              post(targetUploadUri)
                  .setHeaders(
                      HttpHeaders.builder()
                          .addHeader(
                              CONTENT_TYPE, Objects.requireNonNull(mBody.contentType()).toString())
                          .addHeader("X-Atlassian-Token", "no-check")
                          .build())
                  .setRequestBody(ByteString.copyFrom(sink.readByteArray()))
                  .build(),
              networkService);

      if (response.bodyString().isPresent()) {
        String body = response.bodyString().get();
        if (response.status().code() == HttpStatus.OK.code()
            && body.contains("The zip file did not contain an entry")
            && body.contains("exportDescriptor.properties")) {
          return true;
        }
      } else {
        return false;
      }

    } catch (Exception e) {
      logger.atWarning().log("Failed to send request: %s", e.getMessage());
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
                        .setValue("CVE-2023-22518"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("Atlassian Confluence Data Center Improper Authorization CVE-2023-22515")
                .setDescription(
                    "This Improper Authorization vulnerability allows an unauthenticated attacker"
                        + " to reset Confluence and create a Confluence instance administrator"
                        + " account.")
                .setRecommendation(
                    "Patch the confluence version to one of the following versions: "
                        + "7.19.16, 8.3.4, 8.4.4, 8.5.3, 8.6.1"))
        .build();
  }
}
