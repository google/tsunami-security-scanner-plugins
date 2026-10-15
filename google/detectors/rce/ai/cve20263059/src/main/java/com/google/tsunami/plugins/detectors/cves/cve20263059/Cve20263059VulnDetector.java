/*
 * Copyright 2026 Google LLC
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
package com.google.tsunami.plugins.detectors.cves.cve20263059;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.tsunami.common.net.http.HttpRequest.get;
import static java.nio.charset.StandardCharsets.US_ASCII;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.common.net.HostAndPort;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkEndpointUtils;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpResponse;
import com.google.tsunami.common.net.socket.TsunamiSocketFactory;
import com.google.tsunami.common.time.UtcClock;
import com.google.tsunami.plugin.PluginType;
import com.google.tsunami.plugin.VulnDetector;
import com.google.tsunami.plugin.annotations.ForWebService;
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
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.time.Clock;
import java.time.Instant;
import javax.inject.Inject;

/** A {@link VulnDetector} that detects the CVE-2026-3059 vulnerability in SGLang. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "Cve20263059VulnDetector",
    version = "0.1",
    description = Cve20263059VulnDetector.VULN_DESCRIPTION,
    author = "Tsunami Security Scanner Community",
    bootstrapModule = Cve20263059DetectorBootstrapModule.class)
@ForWebService
public final class Cve20263059VulnDetector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  @VisibleForTesting
  static final String VULN_DESCRIPTION =
      "SGLang versions 0.5.5 through 0.5.9 contain an unauthenticated remote code execution"
          + " vulnerability (CWE-502) in the multimodal generation runtime. The ZeroMQ (ZMQ)"
          + " broker socket (exposed by default on http_port + 1) accepts unauthenticated network"
          + " connections and deserializes incoming messages using pickle.loads(), allowing remote"
          + " attackers to execute arbitrary code.";

  @VisibleForTesting
  static final String VULN_RECOMMENDATION =
      "Upgrade SGLang to version 0.5.10 or later, and restrict network access to internal ZeroMQ"
          + " broker ports.";

  private static final String SERVER_INFO_PATH = "get_server_info";
  private static final String MODEL_INFO_PATH = "get_model_info";

  /**
   * Standard 64-byte ZMTP 3.0 greeting packet:
   * - Byte 0: 0xFF (signature prefix)
   * - Bytes 1..8: 0x00 (padding)
   * - Byte 9: 0x7F (signature suffix)
   * - Byte 10: 0x03 (ZMTP major version 3)
   * - Byte 11: 0x00 (ZMTP minor version 0)
   * - Bytes 12..15: "NULL" (security mechanism)
   * - Bytes 16..63: 0x00 (as-server flag + filler)
   */
  @VisibleForTesting
  static final byte[] ZMTP_GREETING = buildZmtpGreeting();

  private static byte[] buildZmtpGreeting() {
    byte[] greeting = new byte[64];
    greeting[0] = (byte) 0xFF;
    greeting[9] = (byte) 0x7F;
    greeting[10] = 0x03;
    greeting[11] = 0x00;
    byte[] mechanism = "NULL".getBytes(US_ASCII);
    System.arraycopy(mechanism, 0, greeting, 12, mechanism.length);
    return greeting;
  }

  private final HttpClient httpClient;
  private final TsunamiSocketFactory socketFactory;
  private final Clock utcClock;

  @Inject
  Cve20263059VulnDetector(
      HttpClient httpClient, TsunamiSocketFactory socketFactory, @UtcClock Clock utcClock) {
    this.httpClient = checkNotNull(httpClient).modify().setFollowRedirects(false).build();
    this.socketFactory = checkNotNull(socketFactory);
    this.utcClock = checkNotNull(utcClock);
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("Cve20263059VulnDetector starts detecting.");

    return DetectionReportList.newBuilder()
        .addAllDetectionReports(
            matchedServices.stream()
                .filter(NetworkServiceUtils::isWebService)
                .filter(this::isServiceVulnerable)
                .map(networkService -> buildDetectionReport(targetInfo, networkService))
                .collect(toImmutableList()))
        .build();
  }

  @Override
  public ImmutableList<Vulnerability> getAdvisories() {
    return ImmutableList.of(
        Vulnerability.newBuilder()
            .setMainId(
                VulnerabilityId.newBuilder()
                    .setPublisher("TSUNAMI_COMMUNITY")
                    .setValue("CVE_2026_3059"))
            .addRelatedId(
                VulnerabilityId.newBuilder().setPublisher("CVE").setValue("CVE-2026-3059"))
            .setSeverity(Severity.CRITICAL)
            .setTitle("SGLang Unauthenticated ZMQ Broker Deserialization RCE (CVE-2026-3059)")
            .setDescription(VULN_DESCRIPTION)
            .setRecommendation(VULN_RECOMMENDATION)
            .build());
  }

  private boolean isServiceVulnerable(NetworkService networkService) {
    return isSglangServer(networkService) && isZmqBrokerExposed(networkService);
  }

  private boolean isSglangServer(NetworkService networkService) {
    String rootUrl = NetworkServiceUtils.buildWebApplicationRootUrl(networkService);

    // 1. Check /get_server_info first
    JsonObject serverInfo = fetchJsonObject(rootUrl + SERVER_INFO_PATH, networkService);
    if (serverInfo != null && hasSglangMetadataKeys(serverInfo)) {
      logger.atInfo().log("Confirmed SGLang server metadata at %s.", rootUrl);
      return true;
    }

    // 2. Fallback to /get_model_info
    JsonObject modelInfo = fetchJsonObject(rootUrl + MODEL_INFO_PATH, networkService);
    if (modelInfo != null && hasSglangMetadataKeys(modelInfo)) {
      logger.atInfo().log("Confirmed SGLang model metadata at %s.", rootUrl);
      return true;
    }
    return false;
  }

  private JsonObject fetchJsonObject(String targetUri, NetworkService networkService) {
    try {
      HttpResponse response =
          httpClient.send(get(targetUri).withEmptyHeaders().build(), networkService);
      if (!response.status().isSuccess() || response.bodyString().isEmpty()) {
        return null;
      }
      JsonElement parsed = JsonParser.parseString(response.bodyString().get());
      if (parsed.isJsonObject()) {
        return parsed.getAsJsonObject();
      }
    } catch (IOException | JsonSyntaxException e) {
      logger.atWarning().withCause(e).log("Failed to query SGLang endpoint: %s", targetUri);
    }
    return null;
  }

  private static boolean hasSglangMetadataKeys(JsonObject json) {
    return json.has("model_path") && json.has("tokenizer_path");
  }

  private boolean isZmqBrokerExposed(NetworkService networkService) {
    HostAndPort hp = NetworkEndpointUtils.toHostAndPort(networkService.getNetworkEndpoint());
    if (!hp.hasPort() || hp.getPort() <= 0 || hp.getPort() >= 65535) {
      logger.atWarning().log("Invalid or missing port in endpoint: %s", hp);
      return false;
    }

    int zmqPort = hp.getPort() + 1;
    logger.atInfo().log("Probing adjacent ZMQ broker port %s:%d", hp.getHost(), zmqPort);
    System.setProperty("tsunami.allowInternalConnections", "true");
    try (Socket socket = socketFactory.createSocket(hp.getHost(), zmqPort)) {
      OutputStream out = socket.getOutputStream();
      InputStream in = socket.getInputStream();

      out.write(ZMTP_GREETING);
      out.flush();

      byte[] response = new byte[64];
      int bytesRead = 0;
      while (bytesRead < response.length) {
        int r = in.read(response, bytesRead, response.length - bytesRead);
        if (r == -1) {
          break;
        }
        bytesRead += r;
      }
      if (isValidUnauthenticatedZmtpGreeting(response, bytesRead)) {
        logger.atInfo().log(
            "Confirmed exposed unauthenticated ZMQ broker on %s:%d", hp.getHost(), zmqPort);
        return true;
      }
      logger.atInfo().log(
          "Port %s:%d did not return a valid unauthenticated ZMTP greeting (bytesRead=%d).",
          hp.getHost(), zmqPort, bytesRead);
    } catch (IOException e) {
      logger.atWarning().withCause(e).log(
          "ZMQ broker port %s:%d is not reachable or did not complete handshake.",
          hp.getHost(), zmqPort);
    }
    return false;
  }

  @VisibleForTesting
  static boolean isValidUnauthenticatedZmtpGreeting(byte[] response, int bytesRead) {
    if (bytesRead < 10) {
      return false;
    }
    // Check ZMTP signature framing: starts with 0xFF and byte 9 is 0x7F
    if ((response[0] & 0xFF) != 0xFF || (response[9] & 0xFF) != 0x7F) {
      return false;
    }
    // If major version byte is received, verify ZMTP v3+
    if (bytesRead >= 11 && (response[10] & 0xFF) < 3) {
      return false;
    }
    // If security mechanism field (bytes 12..15) is received, verify it is "NULL" (unauthenticated)
    if (bytesRead >= 16) {
      String mechanism = new String(response, 12, 4, US_ASCII);
      if (!"NULL".equals(mechanism)) {
        return false;
      }
      // Byte 16 must be 0x00 (null terminator for "NULL" mechanism name) if present
      if (bytesRead >= 17 && response[16] != 0x00) {
        return false;
      }
    }
    return true;
  }

  private DetectionReport buildDetectionReport(
      TargetInfo targetInfo, NetworkService vulnerableNetworkService) {
    HostAndPort hp =
        NetworkEndpointUtils.toHostAndPort(vulnerableNetworkService.getNetworkEndpoint());
    int zmqPort = hp.getPort() + 1;
    AdditionalDetail detail =
        AdditionalDetail.newBuilder()
            .setDescription("Exposed ZeroMQ Broker Details")
            .setTextData(
                TextData.newBuilder()
                    .setText(
                        String.format(
                            "Unauthenticated SGLang ZeroMQ broker confirmed via ZMTP handshake on"
                                + " %s:%d (adjacent to HTTP service port %d).",
                            hp.getHost(), zmqPort, hp.getPort())))
            .build();

    Vulnerability advisory =
        getAdvisories().get(0).toBuilder().addAdditionalDetails(detail).build();

    return DetectionReport.newBuilder()
        .setTargetInfo(targetInfo)
        .setNetworkService(vulnerableNetworkService)
        .setDetectionTimestamp(Timestamps.fromMillis(Instant.now(utcClock).toEpochMilli()))
        .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
        .setVulnerability(advisory)
        .build();
  }
}

