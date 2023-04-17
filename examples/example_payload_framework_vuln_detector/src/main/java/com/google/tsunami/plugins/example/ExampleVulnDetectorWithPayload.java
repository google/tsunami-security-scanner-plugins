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
package com.google.tsunami.plugins.example;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.tsunami.common.data.NetworkEndpointUtils.toUriAuthority;

import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.protobuf.ByteString;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpRequest;
import com.google.tsunami.common.net.http.HttpResponse;
import com.google.tsunami.common.time.UtcClock;
import com.google.tsunami.plugin.PluginType;
import com.google.tsunami.plugin.VulnDetector;
import com.google.tsunami.plugin.annotations.PluginInfo;
import com.google.tsunami.plugin.payload.Payload;
import com.google.tsunami.plugin.payload.PayloadGenerator;
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
import java.time.Instant;
import javax.inject.Inject;

/** An example VulnDetector plugin that uses the Tsunami {@link PayloadGenerator}. */
// PluginInfo tells Tsunami scanning engine basic information about your plugin.
@PluginInfo(
    // Which type of plugin this is.
    type = PluginType.VULN_DETECTION,
    // A human readable name of your plugin.
    name = "ExampleVulnDetectorWithPayload",
    // Current version of your plugin.
    version = "0.1",
    // Detailed description about what this plugin does.
    description = "This is an example plugin that utilizes Tsunami's payload generation framework.",
    // Author of this plugin.
    author = "Alice (alice@company.com)",
    // How should Tsunami scanner bootstrap your plugin.
    bootstrapModule = ExampleVulnDetectorWithPayloadBootstrapModule.class)
// Optionally, each VulnDetector can be annotated by service filtering annotations. For example, if
// the VulnDetector should only be executed when the scan target is running Jenkins, then add the
// following @ForSoftware annotation.
// @ForSoftware(name = "Jenkins")
public final class ExampleVulnDetectorWithPayload implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private final Clock utcClock;
  private final HttpClient httpClient;
  private final PayloadGenerator payloadGenerator;

  // Tsunami scanner relies heavily on Guice framework. So all the utility dependencies of your
  // plugin must be injected through the constructor of the detector. Notably, the Payload
  // generator is injected this way.
  @Inject
  ExampleVulnDetectorWithPayload(
      @UtcClock Clock utcClock, HttpClient httpClient, PayloadGenerator payloadGenerator) {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient).modify().setFollowRedirects(false).build();
    this.payloadGenerator = checkNotNull(payloadGenerator);
  }

  // This is the main entry point of your VulnDetector. Both parameters will be populated by the
  // scanner. targetInfo contains the general information about the scan target. matchedServices
  // parameter contains all the network services that matches the service filtering annotations
  // mentioned earlier. If no filtering annotations added, then matchedServices parameter contains
  // all exposed network services on the scan target.
  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("ExampleVulnDetectorWithPayload starts detecting.");

    return DetectionReportList.newBuilder()
        .addAllDetectionReports(
            matchedServices.stream()
                // Check individual NetworkService whether it is vulnerable.
                .filter(this::isServiceVulnerable)
                // Build DetectionReport message for vulnerable services.
                .map(networkService -> buildDetectionReport(targetInfo, networkService))
                .collect(toImmutableList()))
        .build();
  }

  // Checks whether a given network service is vulnerable. Real detection logic implemented here.
  private boolean isServiceVulnerable(NetworkService networkService) {

    // Tell the PayloadGenerator what kind of vulnerability we are detecting so that it returns the
    // best payload for that environment. See the proto definition to understand what these options
    // mean.
    PayloadGeneratorConfig config =
        PayloadGeneratorConfig.newBuilder()
            .setVulnerabilityType(PayloadGeneratorConfig.VulnerabilityType.REFLECTIVE_RCE)
            .setInterpretationEnvironment(
                PayloadGeneratorConfig.InterpretationEnvironment.LINUX_SHELL)
            .setExecutionEnvironment(
                PayloadGeneratorConfig.ExecutionEnvironment.EXEC_INTERPRETATION_ENVIRONMENT)
            .build();

    // Pass in the config to get the actual payload from the generator.
    // If the Tsunami callback server is configured, the generator will always try to return a
    // callback-enabled payload.
    Payload payload = this.payloadGenerator.generate(config);

    // Your detector should always handle getting a payload that doesn't use the callback server
    // since not all Tsunami instances will have the callback server configured.
    if (!payload.getPayloadAttributes().getUsesCallbackServer()) {
      return false;
    }

    // payload.getPayload() returns the actual payload String. You may need to
    // serialize/encode/format it to suit the specific vulnerability. Here, we inject it into a
    // shell command.
    String commandToInject = String.format("sh\", \"-c\", \"%s", payload.getPayload());

    // Inject the payload into the vulnerable service
    String targetUri =
        String.format(
            "http://%s%s",
            toUriAuthority(networkService.getNetworkEndpoint()), "/vulnerable-endpoint");
    HttpRequest req =
        HttpRequest.put(targetUri)
            .withEmptyHeaders()
            .setRequestBody(ByteString.copyFromUtf8(commandToInject))
            .build();

    try {
      HttpResponse res = this.httpClient.send(req, networkService);

      // We can then validate whether the payload was executed using payload.checkWithExecuted. If
      // so, the vulnerability is detected! Depending on the vulnerability type, checkIfExecuted
      // may not need any input.
      return res.status().isSuccess() && payload.checkIfExecuted(res.bodyBytes());
    } catch (IOException e) {
      return false;
    }
  }

  // This builds the DetectionReport message for a specific vulnerable network service.
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
                        .setPublisher("vulnerability_id_publisher")
                        .setValue("VULNERABILITY_ID"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("Vulnerability Title")
                .setDescription("Verbose description of the issue")
                .setRecommendation("Verbose recommended solution")
                .addAdditionalDetails(
                    AdditionalDetail.newBuilder()
                        .setTextData(
                            TextData.newBuilder().setText("Some additional technical details."))))
        .build();
  }
}
