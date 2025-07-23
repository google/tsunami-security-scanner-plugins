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
package com.google.tsunami.plugins.detectors.rce.cve202532433;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.tsunami.plugins.detectors.rce.cve202532433.SshClient.connectAndExecuteCommand;

import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.common.util.concurrent.Uninterruptibles;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.time.UtcClock;
import com.google.tsunami.plugin.PluginType;
import com.google.tsunami.plugin.VulnDetector;
import com.google.tsunami.plugin.annotations.PluginInfo;
import com.google.tsunami.plugin.payload.Payload;
import com.google.tsunami.plugin.payload.PayloadGenerator;
import com.google.tsunami.plugins.detectors.rce.cve202532433.Annotations.OobSleepDuration;
import com.google.tsunami.plugins.detectors.rce.cve202532433.Annotations.SocketFactoryInstance;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.PayloadGeneratorConfig;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.TransportProtocol;
import com.google.tsunami.proto.Vulnerability;
import com.google.tsunami.proto.VulnerabilityId;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import javax.inject.Inject;
import javax.net.SocketFactory;

/** A Tsunami plugin that detects Erlang/OTP SSH RCE vulnerability CVE-2025-32433. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "ErlangOtpSshCve2025324336Detector",
    version = "0.1",
    description = "This plugin detects the Erlang/OTP SSH CVE-2025-32433 RCE vulnerability.",
    author = "mr-mosi",
    bootstrapModule = ErlangOtpSshCve2025324336DetectorBootstrapModule.class)
public final class ErlangOtpSshCve2025324336Detector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private final Clock utcClock;
  private final PayloadGenerator payloadGenerator;
  private final SocketFactory socketFactory;
  private final int oobSleepDuration;

  @Inject
  ErlangOtpSshCve2025324336Detector(
      @UtcClock Clock utcClock,
      PayloadGenerator payloadGenerator,
      @SocketFactoryInstance SocketFactory socketFactory,
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
                    .setValue("CVE-2025-32433"))
            .setSeverity(Severity.CRITICAL)
            .setTitle("Erlang/OTP SSH Remote Code Execution Vulnerability (CVE-2025-32433)")
            .setDescription(
                "Erlang/OTP before OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20 contains a command"
                    + " injection vulnerability in the SSH subsystem. An unauthenticated attacker"
                    + " can exploit this flaw by sending a crafted SSH message, leading to remote"
                    + " code execution on the affected system.")
            .setRecommendation(
                "Upgrade Erlang/OTP to version OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20 or"
                    + " later to address CVE-2025-32433. Additionally, restrict or remove SSH"
                    + " exposure to untrusted networks to reduce risk.")
            .addRelatedId(
                VulnerabilityId.newBuilder().setPublisher("CVE").setValue("CVE-2025-32433"))
            .build());
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("Starting detection of Erlang/OTP SSH CVE-2025-32433.");

    return DetectionReportList.newBuilder()
        .addAllDetectionReports(
            matchedServices.stream()
                .filter(this::isErlangOtpSshService)
                .filter(this::isServiceVulnerable)
                .map(service -> buildDetectionReport(targetInfo, service))
                .collect(toImmutableList()))
        .build();
  }

  private boolean isErlangOtpSshService(NetworkService service) {
    logger.atInfo().log("Checking if the service is a Erlang/OTP SSH service.");
    if (!(service.getServiceName().equalsIgnoreCase("ssh")
        && service.getTransportProtocol() == TransportProtocol.TCP)) {
      logger.atInfo().log("Service is not SSH");
      return false;
    }
    var serviceIp = service.getNetworkEndpoint().getIpAddress().getAddress();
    var servicePort = service.getNetworkEndpoint().getPort().getPortNumber();
    try (var socket = socketFactory.createSocket(serviceIp, servicePort)) {
      // Connecting to SSH server...
      socket.setSoTimeout(5000);
      OutputStream out = socket.getOutputStream();
      InputStream in = socket.getInputStream();
      // Banner exchange
      out.write("SSH-2.0-OpenSSH_8.9\r\n".getBytes());
      out.flush();
      byte[] bannerBuffer = new byte[1024];
      int bytesRead = in.read(bannerBuffer);
      if (bytesRead > 0) {
        String banner = new String(bannerBuffer, 0, bytesRead).trim();
        if (!banner.startsWith("SSH-2.0-Erlang/")) {
          logger.atWarning().log(
              "Service at %s:%s is not an Erlang SSH server.", serviceIp, servicePort);
          socket.close();
          return false;
        }
        socket.close();
        return true;
      }
    } catch (IOException e) {
      logger.atWarning().withCause(e).log(
          "Failed to send payload to service at %s:%s.", serviceIp, servicePort);
    }
    return true;
  }

  private boolean isServiceVulnerable(NetworkService service) {
    logger.atInfo().log("Checking if Erlang/OTP SSH service is vulnerable.");

    Payload payload = generateCallbackServerPayload();
    // Check callback server is enabled
    if (!payload.getPayloadAttributes().getUsesCallbackServer()) {
      logger.atInfo().log(
          "The Tsunami callback server is not setup for this environment, so we cannot confirm the"
              + " RCE callback");
      return false;
    }
    logger.atInfo().log("Callback server is available!");

    String command = payload.getPayload();

    var serviceIp = service.getNetworkEndpoint().getIpAddress().getAddress();
    var servicePort = service.getNetworkEndpoint().getPort().getPortNumber();
    try (var socket = socketFactory.createSocket(serviceIp, servicePort)) {
      if (!connectAndExecuteCommand(socket, command, logger)) {
        return false;
      }
      Uninterruptibles.sleepUninterruptibly(Duration.ofSeconds(oobSleepDuration));
      return payload.checkIfExecuted();
    } catch (IOException e) {
      logger.atWarning().withCause(e).log(
          "Failed to send payload to service at %s:%s.", serviceIp, servicePort);
      return false;
    }
  }

  private Payload generateCallbackServerPayload() {
    PayloadGeneratorConfig config =
        PayloadGeneratorConfig.newBuilder()
            .setVulnerabilityType(PayloadGeneratorConfig.VulnerabilityType.BLIND_RCE)
            .setInterpretationEnvironment(
                PayloadGeneratorConfig.InterpretationEnvironment.LINUX_SHELL)
            .setExecutionEnvironment(
                PayloadGeneratorConfig.ExecutionEnvironment.EXEC_INTERPRETATION_ENVIRONMENT)
            .build();

    return this.payloadGenerator.generate(config);
  }

  private DetectionReport buildDetectionReport(TargetInfo targetInfo, NetworkService service) {
    return DetectionReport.newBuilder()
        .setTargetInfo(targetInfo)
        .setNetworkService(service)
        .setDetectionTimestamp(Timestamps.fromMillis(Instant.now(utcClock).toEpochMilli()))
        .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
        .setVulnerability(this.getAdvisories().getFirst())
        .build();
  }
}
