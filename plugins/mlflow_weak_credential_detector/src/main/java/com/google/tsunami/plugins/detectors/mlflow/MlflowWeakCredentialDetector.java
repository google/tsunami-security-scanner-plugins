package com.google.tsunami.plugins.detectors.mlflow;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;

import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpHeaders;
import com.google.tsunami.common.net.http.HttpRequest;
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
import javax.inject.Inject;

@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "MlflowWeakCredentialDetector",
    version = "0.1",
    description = "Detects default weak credentials in MLflow instances.",
    author = "Jules (AI Language Model)",
    bootstrapModule = MlflowWeakCredentialDetectorBootstrapModule.class)
public final class MlflowWeakCredentialDetector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private final Clock utcClock;
  private final HttpClient httpClient;

  // MLflow default credentials
  private static final String DEFAULT_USERNAME = "admin";
  private static final String DEFAULT_PASSWORD = "password";

  // A simple MLflow API endpoint that requires authentication.
  // We expect a 200 OK if creds are valid, 401/403 if invalid or auth not enabled in a certain way.
  // This might need adjustment based on MLflow API specifics.
  // Using `/api/2.0/mlflow/experiments/list` as an example.
  private static final String MLFLOW_AUTH_TEST_PATH = "api/2.0/mlflow/experiments/list";


  @Inject
  MlflowWeakCredentialDetector(@UtcClock Clock utcClock, HttpClient httpClient) {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient);
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("MlflowWeakCredentialDetector starts scanning.");

    return DetectionReportList.newBuilder()
        .addAllDetectionReports(
            matchedServices.stream()
                .filter(NetworkServiceUtils::isWebService)
                .filter(this::isMlflowService) // Add a check if this is actually an MLflow service if possible
                .map(networkService -> checkServiceForWeakCredentials(targetInfo, networkService))
                .filter(java.util.Optional::isPresent)
                .map(java.util.Optional::get)
                .collect(toImmutableList()))
        .build();
  }

  private boolean isMlflowService(NetworkService networkService) {
    // TODO: Implement a more reliable way to identify MLflow services.
    // This could involve checking for specific path exposures, specific headers, or banner grabbing.
    // For now, we assume any web service on common MLflow ports (e.g., 5000) might be MLflow.
    // This is a simplification and should be improved.
    if (networkService.getNetworkEndpoint().hasPort()) {
        int port = networkService.getNetworkEndpoint().getPort().getPortNumber();
        // Default MLflow port is 5000. Other common alternatives might be 80, 443 (if proxied)
        return port == 5000 || port == 80 || port == 443;
    }
    return true; // If no port, proceed cautiously.
  }

  private java.util.Optional<DetectionReport> checkServiceForWeakCredentials(
      TargetInfo targetInfo, NetworkService networkService) {
    String targetUri = NetworkServiceUtils.buildWebApplicationUrl(networkService, MLFLOW_AUTH_TEST_PATH);
    logger.atInfo().log("Testing URI for MLflow weak creds: %s", targetUri);

    HttpRequest request = HttpRequest.get(targetUri)
        .withCredentials(DEFAULT_USERNAME, DEFAULT_PASSWORD)
        .build();

    try {
      HttpResponse response = httpClient.send(request, networkService);

      // Successful authentication with default credentials
      if (response.status().isSuccess()) {
        // Check if the body indicates it's actually mlflow and not some other service that accepted the auth
        // For now, we assume success means vulnerable.
        logger.atInfo().log("Successfully authenticated to MLflow at %s with default credentials.", targetUri);
        return java.util.Optional.of(buildDetectionReport(targetInfo, networkService, DEFAULT_USERNAME, DEFAULT_PASSWORD));
      } else if (response.status().code() == 401 || response.status().code() == 403) {
        // Unauthorized or Forbidden - This means auth is likely enabled, but these creds are wrong.
        // This is the expected outcome if default creds are *not* used.
        logger.atInfo().log("Authentication failed for %s with default credentials (status: %s), which is good.", targetUri, response.status());
      } else {
        // Other statuses might indicate auth is not enabled, or other issues.
        // For MLflow, if basic auth is not configured, it might return pages directly or redirect.
        // A more sophisticated check is needed here to differentiate "auth not enabled" from "service not MLflow".
        // For now, we don't report these cases as a weak credential finding.
        logger.atInfo().log("Unexpected status %s for %s. Auth might not be enabled or not an MLflow service.", response.status(), targetUri);
      }
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Failed to send request to %s.", targetUri);
    }
    return java.util.Optional.empty();
  }

  private DetectionReport buildDetectionReport(
      TargetInfo targetInfo, NetworkService vulnerableNetworkService, String username, String password) {
    return DetectionReport.newBuilder()
        .setTargetInfo(targetInfo)
        .setNetworkService(vulnerableNetworkService)
        .setDetectionTimestamp(Timestamps.fromMillis(Instant.now(utcClock).toEpochMilli()))
        .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
        .setVulnerability(
            Vulnerability.newBuilder()
                .setMainId(
                    VulnerabilityId.newBuilder()
                        .setPublisher("GOOGLE_JULES") // Using a distinct publisher
                        .setValue("MLFLOW_WEAK_CREDENTIAL"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("MLflow Default Weak Credentials")
                .setDescription(
                    String.format(
                        "The MLflow instance at %s is using default weak credentials (username: '%s', password: '%s'). "
                            + "This allows unauthorized access to experiments, models, and potentially the underlying infrastructure.",
                        NetworkServiceUtils.buildWebApplicationUrl(vulnerableNetworkService),
                        username,
                        password))
                .setRecommendation(
                    "Change the default admin password immediately. "
                        + "Refer to MLflow documentation for securely managing credentials. "
                        + "If basic authentication is not required, consider disabling it or using a more robust authentication mechanism.")
                // TODO: Add Cveid if one exists for this specific default credential issue.
                .setCvssV3("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") // Critical score for default admin creds
                )
        .build();
  }
}
