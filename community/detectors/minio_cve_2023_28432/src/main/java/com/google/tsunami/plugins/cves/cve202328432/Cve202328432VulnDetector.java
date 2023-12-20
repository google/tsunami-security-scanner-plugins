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
package com.google.tsunami.plugins.cves.cve202328432;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.base.Preconditions.checkState;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.common.net.HttpHeaders.USER_AGENT;
import static com.google.tsunami.common.data.NetworkEndpointUtils.toUriAuthority;
import static com.google.tsunami.common.net.http.HttpClient.TSUNAMI_USER_AGENT;

import com.google.auto.value.AutoValue;
import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpHeaders;
import com.google.tsunami.common.net.http.HttpMethod;
import com.google.tsunami.common.net.http.HttpRequest;
import com.google.tsunami.common.net.http.HttpResponse;
import com.google.tsunami.common.time.UtcClock;
import com.google.tsunami.plugin.PluginType;
import com.google.tsunami.plugin.VulnDetector;
import com.google.tsunami.plugin.annotations.PluginInfo;
import com.google.tsunami.plugins.cves.cve202328432.minio.Digest;
import com.google.tsunami.plugins.cves.cve202328432.minio.Signer;
import com.google.tsunami.plugins.cves.cve202328432.minio.Time;
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
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.Optional;
import javax.inject.Inject;

/** A VulnDetector plugin to find instances of CVE 2023-28432. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "CVE202328432MinIOCluster",
    version = "0.1",
    description =
        "In a vulnerable cluster deployment, MinIO returns all environment variables, including"
            + " MINIO_SECRET_KEY and MINIO_ROOT_PASSWORD, resulting in information disclosure."
            + " This plugin also checks for unchanged default passwords, which might not be shown"
            + " in the configuration",
    author = "Hans-Martin Münch (muench@mogwailabs.de)",
    bootstrapModule = Cve202328432VulnDetectorBootstrapModule.class)
public final class Cve202328432VulnDetector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private final Clock utcClock;
  private final HttpClient httpClient;

  private final String defaultUser = "minioadmin";
  private final String defaultPassword = "minioadmin";

  @VisibleForTesting
  public static final String DESCRIPTION =
      "MinIO deployments have a default user with access to all actions and resources on the"
          + " deployment, regardless of the configured identity manager."
          + " These credentials are set through environment variables that are checked on startup."
          + " If the environment variables are not set, default credentials (minioadmin:minioadmin)"
          + " are used."
          + " Due to a vulnerability in an API endpoint, MinIO returns all environment variables,"
          + " including MINIO_SECRET_KEY and MINIO_ROOT_PASSWORD, resulting in information"
          + " disclosure.";

  @VisibleForTesting
  public static final String RECOMMENDATION =
      "Update to the latest MinIO version (>= RELEASE.2023-03-20T20-16-18Z)."
          + " The MINIO_SECRET_KEY and / or MINIO_ROOT_PASSWORD of the affected MinIO instance must"
          + " be changed";

  private static final String MINIO_VERIFY_PATH = "minio/bootstrap/v1/verify";

  @Inject
  Cve202328432VulnDetector(@UtcClock Clock utcClock, HttpClient httpClient) {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient);
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("CVE202328432 (MinIO cluster disclosure) starts detecting.");

    DetectionReportList detectionReports =
        DetectionReportList.newBuilder()
            .addAllDetectionReports(
                matchedServices.stream()
                    .filter(Cve202328432VulnDetector::isWebServiceOrUnknownService)
                    .map(this::checkEndpointForNetworkService)
                    .filter(EndpointProbingResult::isVulnerable)
                    .map(probingResult -> buildDetectionReport(targetInfo, probingResult))
                    .collect(toImmutableList()))
            .build();

    logger.atInfo().log(
        "CVE202328432 (MinIO cluster disclosure) finished, detected '%d' vulns.",
        detectionReports.getDetectionReportsCount());
    return detectionReports;
  }

  private static boolean isWebServiceOrUnknownService(NetworkService networkService) {
    return networkService.getServiceName().isEmpty()
        || NetworkServiceUtils.isWebService(networkService)
        || NetworkServiceUtils.getServiceName(networkService).equals("unknown")
        || NetworkServiceUtils.getServiceName(networkService).equals("cslistener");
  }

  private static String buildTargetUrl(NetworkService networkService) {
    if (NetworkServiceUtils.isWebService(networkService)) {
      return NetworkServiceUtils.buildWebApplicationRootUrl(networkService);
    }
    // Assume the service uses HTTP protocol when the scanner cannot identify the actual service.
    return "http://" + toUriAuthority(networkService.getNetworkEndpoint()) + "/";
  }

  private EndpointProbingResult checkEndpointForNetworkService(NetworkService networkService) {
    String baseUrl = buildTargetUrl(networkService);
    String targetUri = String.format("%s%s", baseUrl, MINIO_VERIFY_PATH);
    boolean usesDefaultPw = false;

    try {
      // Try the default user / password
      // this request always works, even if access to the VERIFY path is blocked
      String requestDate = ZonedDateTime.now(ZoneOffset.UTC).format(Time.AMZ_DATE_FORMAT);
      HttpRequest signedRequest =
          buildSignedHttpRequest(baseUrl, requestDate, this.defaultUser, this.defaultPassword);
      HttpResponse authResponse = this.httpClient.send((signedRequest));
      // Successful authentication through leaked or default credentials
      if (authResponse.status().isSuccess()
          && authResponse.bodyString().isPresent()
          && authResponse.bodyString().get().contains("ListAllMyBucketsResult")) {
        usesDefaultPw = true;
      }
    } catch (java.io.IOException e) {
      logger.atWarning().withCause(e).log("Unable to send request at %s", baseUrl);
      usesDefaultPw = false;
    }

    try {
      // try to access the verify service endpoint
      HttpResponse response =
          httpClient.send(HttpRequest.post(targetUri).withEmptyHeaders().build(), networkService);
      if (response.status().isSuccess() && response.bodyJson().isPresent()) {
        JsonObject jsonResponse = (JsonObject) response.bodyJson().get();

        if (jsonResponse.has("MinioEnv")) {
          JsonObject minioEnv = jsonResponse.getAsJsonObject("MinioEnv");

          // Older/mitigated MinIO instances used "MINIO_ACCESS_KEY" and "MINIO_SECRET_KEY"
          // (deprecated)
          // Newer instances use "MINIO_ROOT_USER" and "MINIO_ROOT_PASSWORD".
          // We need to check for both.
          JsonElement minioAccessKey = minioEnv.get("MINIO_ACCESS_KEY");
          JsonElement minioSecretKey = minioEnv.get("MINIO_SECRET_KEY");
          JsonElement minioRootUser = minioEnv.get("MINIO_ROOT_USER");
          JsonElement minioRootPassword = minioEnv.get("MINIO_ROOT_PASSWORD");

          String testKey = this.defaultUser;
          String testSecret = this.defaultPassword;

          // We have an old instance that still used the deprecated MINIO_ACCESS_KEY and
          // MINIO_SECRET_KEY
          if (minioAccessKey != null && minioSecretKey != null) {
            testKey = minioAccessKey.getAsString();
            testSecret = minioSecretKey.getAsString();
          } else if (minioRootUser != null && minioRootPassword != null) {
            // Case 2:
            // New instance with MINIO_ROOT_USER and MINIO_ROOT_PASSWORD
            testKey = minioRootUser.getAsString();
            testSecret = minioRootPassword.getAsString();
          }

          // try to authenticate with the leaked credentials
          // or the default credentials of no creds were discovered
          String requestDate = ZonedDateTime.now(ZoneOffset.UTC).format(Time.AMZ_DATE_FORMAT);
          HttpRequest signedRequest =
              buildSignedHttpRequest(baseUrl, requestDate, testKey, testSecret);

          HttpResponse authResponse = this.httpClient.send((signedRequest));

          // Successful authentication through leaked or default credentials
          if (authResponse.status().isSuccess()
              && authResponse.bodyString().isPresent()
              && authResponse.bodyString().get().contains("ListAllMyBucketsResult")) {

            return EndpointProbingResult.builder()
                .setIsVulnerable(true)
                .setUsesDefaultPassword(usesDefaultPw)
                .setAuthenticationSuccessful(true)
                .setNetworkService(networkService)
                .setVulnerableEndpointResponse(response)
                .build();
          }
        }
      }

      // Were we able to authenticate with default credentials, but unable to access the verify
      // endpoint?
      // Mark it as vulnerable
      if (usesDefaultPw) {
        return EndpointProbingResult.builder()
            .setIsVulnerable(true)
            .setUsesDefaultPassword(usesDefaultPw)
            .setAuthenticationSuccessful(true)
            .setNetworkService(networkService)
            .setVulnerableEndpointResponse(response)
            .build();
      }
    } catch (java.io.IOException e) {
      logger.atWarning().withCause(e).log("Unable to send request at %s", targetUri);
    } catch (java.lang.ClassCastException e) {
      logger.atWarning().withCause(e).log("Unable to parse JSON data, probably no MinIO service");
    }
    return EndpointProbingResult.invulnerableForNetworkService(networkService);
  }

  // MinIO supports the AWS S3 protocol, therefore we need to sign the request with the given
  // credentials
  @VisibleForTesting
  public HttpRequest buildSignedHttpRequest(
      String targetUri, String requestDate, String accessKey, String secretKey) {
    try {

      HttpRequest.Builder signedRequest = HttpRequest.builder();
      signedRequest.setMethod(HttpMethod.GET);
      signedRequest.setUrl(targetUri);

      HttpHeaders.Builder signedRequestHeaders = HttpHeaders.builder();
      signedRequestHeaders.addHeader("Host", new URL(targetUri).getAuthority());

      // SHA 256 value of an empty body.
      signedRequestHeaders.addHeader(USER_AGENT, TSUNAMI_USER_AGENT);
      signedRequestHeaders.addHeader("x-amz-content-sha256", Digest.ZERO_SHA256_HASH);
      signedRequestHeaders.addHeader("x-amz-date", requestDate);

      signedRequest.setHeaders(signedRequestHeaders.build());
      HttpRequest finalRequest =
          Signer.signV4(
              "s3",
              signedRequest.build(),
              "us-east-1",
              accessKey,
              secretKey,
              Digest.ZERO_SHA256_HASH);
      return finalRequest;

    } catch (java.io.IOException e) {
      logger.atWarning().withCause(e).log("Unable to send signed request at %s", targetUri);
      return null;
    } catch (NoSuchAlgorithmException e) {
      logger.atWarning().withCause(e).log("Unable to send signed request , missing algorithm");
      return null;
    } catch (InvalidKeyException e) {
      logger.atWarning().withCause(e).log("Unable to send signed request , invalid key");
      return null;
    }
  }

  // This builds the DetectionReport message for a specific vulnerable network service.
  private DetectionReport buildDetectionReport(
      TargetInfo targetInfo, EndpointProbingResult endpointProbingResult) {
    return DetectionReport.newBuilder()
        .setTargetInfo(targetInfo)
        .setNetworkService(endpointProbingResult.networkService())
        .setDetectionTimestamp(Timestamps.fromMillis(Instant.now(utcClock).toEpochMilli()))
        .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
        .setVulnerability(
            Vulnerability.newBuilder()
                .setMainId(
                    VulnerabilityId.newBuilder()
                        .setPublisher("TSUNAMI_COMMUNITY")
                        .setValue("MINIO_INFORMATION_DISCLOSURE_CLUSTER_ENVIRONMENT"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("MinIO Information Disclosure in Cluster Environment")
                .setDescription(DESCRIPTION)
                .setRecommendation(RECOMMENDATION)
                .addAdditionalDetails(buildAdditionalDetail(endpointProbingResult)))
        .build();
  }

  private static AdditionalDetail buildAdditionalDetail(EndpointProbingResult probingResult) {
    checkState(probingResult.vulnerableEndpointResponse().isPresent());

    String vulnerabilityDetail = "MinIO instances are vulnerable for the following reason(s):";
    if (probingResult.usesDefaultPassword()) {
      vulnerabilityDetail =
          vulnerabilityDetail.concat(" Default credentials (minioadmin:minioadmin) are used.");
    }
    if (probingResult.authenticationSuccessful()) {
      vulnerabilityDetail =
          vulnerabilityDetail.concat(" Leaked credentials enabled authentication bypass.");
    }

    vulnerabilityDetail =
        vulnerabilityDetail.concat(
            " Endpoint Response: "
                + probingResult.vulnerableEndpointResponse().get().bodyString().get());

    return AdditionalDetail.newBuilder()
        .setTextData(TextData.newBuilder().setText(vulnerabilityDetail))
        .build();
  }

  @AutoValue
  abstract static class EndpointProbingResult {
    abstract boolean isVulnerable();

    abstract boolean usesDefaultPassword();

    abstract boolean authenticationSuccessful();

    abstract NetworkService networkService();

    abstract Optional<HttpResponse> vulnerableEndpointResponse();

    static Builder builder() {
      return new AutoValue_Cve202328432VulnDetector_EndpointProbingResult.Builder();
    }

    static EndpointProbingResult invulnerableForNetworkService(NetworkService networkService) {
      return builder()
          .setIsVulnerable(false)
          .setUsesDefaultPassword(false)
          .setAuthenticationSuccessful(false)
          .setNetworkService(networkService)
          .build();
    }

    @AutoValue.Builder
    abstract static class Builder {
      abstract Builder setIsVulnerable(boolean value);

      abstract Builder setAuthenticationSuccessful(boolean value);

      abstract Builder setUsesDefaultPassword(boolean value);

      abstract Builder setNetworkService(NetworkService value);

      abstract Builder setVulnerableEndpointResponse(HttpResponse value);

      abstract EndpointProbingResult build();
    }
  }
}
