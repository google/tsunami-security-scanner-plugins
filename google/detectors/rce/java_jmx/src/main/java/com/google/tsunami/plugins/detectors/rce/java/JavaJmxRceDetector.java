/*
 * Copyright 2020 Google LLC
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
package com.google.tsunami.plugins.detectors.rce.java;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;

import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.common.net.HostAndPort;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkEndpointUtils;
import com.google.tsunami.common.data.NetworkServiceUtils;
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
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.MalformedURLException;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.util.Arrays;
import java.util.UUID;
import javax.inject.Inject;
import javax.management.MBeanServerConnection;
import javax.management.ObjectName;
import javax.management.remote.JMXConnector;
import javax.management.remote.JMXConnectorFactory;
import javax.management.remote.JMXServiceURL;

/** A {@link VulnDetector} that detects unprotected Java JMX servers. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "JavaJmxRceDetector",
    version = "0.1",
    description = "This detector checks for unprotected Java JMX servers with RMI endpoint.",
    author = "Tsunami Team (tsunami-dev@google.com)",
    bootstrapModule = JavaJmxRceDetectorBootstrapModule.class)
public final class JavaJmxRceDetector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private final Clock utcClock;

  @Inject
  JavaJmxRceDetector(@UtcClock Clock utcClock) {
    this.utcClock = checkNotNull(utcClock);
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("JavaJmxRceDetector starts detecting.");

    return DetectionReportList.newBuilder()
        .addAllDetectionReports(
            matchedServices.stream()
                .filter(JavaJmxRceDetector::isRmi)
                .filter(JavaJmxRceDetector::isServiceVulnerable)
                .map(networkService -> buildDetectionReport(targetInfo, networkService))
                .collect(toImmutableList()))
        .build();
  }

  private static boolean isServiceVulnerable(NetworkService networkService) {
    // First create an URL for the JMX service according to
    // https://docs.oracle.com/javase/8/docs/technotes/guides/management/agent.html#gdfci
    JMXServiceURL serviceURL;
    String urlString =
        "service:jmx:rmi:///jndi/rmi://"
            + NetworkEndpointUtils.toUriAuthority(networkService.getNetworkEndpoint())
            + "/jmxrmi";
    try {
      serviceURL = new JMXServiceURL(urlString);
    } catch (MalformedURLException ex) {
      logger.atSevere().log("Invalid URL string for Java JMX service: %s", urlString);
      return false;
    }

    // Second try connecting to the service without any auth config. This can only succeed if the
    // service is a JMX server and unprotected.
    try (JMXConnector connector = JMXConnectorFactory.connect(serviceURL)) {
      connector.connect();
      MBeanServerConnection serverConnection = connector.getMBeanServerConnection();

      // Finally try creating an MBean with class javax.management.loading.MLet, which would allow
      // us instantiating arbitrary MBeans from a remote URL. See
      // https://www.optiv.com/explore-optiv-insights/blog/exploiting-jmx-rmi.
      ObjectName objectName = new ObjectName("MLet#" + UUID.randomUUID(), "id", "1");
      serverConnection.createMBean("javax.management.loading.MLet", objectName);
      logger.atInfo().log("Successfully created a MLet MBean on JMX service %s", urlString);

      // Delete the created MBean.
      serverConnection.unregisterMBean(objectName);
      return true;
    } catch (Exception ex) {
      logger.atFine().log("Failed to run JavaJmxRceDetector for service: %s", urlString);
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
                    VulnerabilityId.newBuilder()
                        .setPublisher("GOOGLE")
                        .setValue("JAVA_UNPROTECTED_JMX_RMI_SERVER"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("Unprotected Java JMX RMI Server")
                .setDescription(
                    "Java Management Extension (JMX) allows remote monitoring and diagnostics for"
                        + " Java applications. Running JMX with unprotected RMI endpoint allows"
                        + " any remote users to create a javax.management.loading.MLet MBean and"
                        + " use it to create new MBeans from arbitrary URLs.")
                .setRecommendation(
                    "Enable authentication and upgrade to the latest JDK environment."))
        .build();
  }

  /**
   * Checks whether the network service is a Java RMI service or unknown.
   *
   * <p>Tsunami currently runs the port scanner nmap with version detection intensity set to 5,
   * which isn't high enough to detect Java RMI services. Therefore we try to identify the RMI
   * service by sending some data and checking the response. This is based on nmap's service probe
   * file: https://svn.nmap.org/nmap/nmap-service-probes
   */
  private static boolean isRmi(NetworkService networkService) {
    if (NetworkServiceUtils.getServiceName(networkService).equals("java-rmi")) {
      return true;
    }

    // Probe the service
    HostAndPort hostAndPort =
        NetworkEndpointUtils.toHostAndPort(networkService.getNetworkEndpoint());

    try {
      Socket socket = new Socket();
      socket.connect(
          new InetSocketAddress(hostAndPort.getHost(), hostAndPort.getPort()), 10 * 1000);

      DataInputStream dataInputStream = new DataInputStream(socket.getInputStream());
      DataOutputStream dataOutputStream = new DataOutputStream(socket.getOutputStream());

      // Send probe
      byte[] probe = {0x4a, 0x52, 0x4d, 0x49, 0x00, 0x02, 0x4b};
      dataOutputStream.write(probe);
      dataOutputStream.flush();

      // Receive response
      byte[] buffer = new byte[1024];
      int bytesRead = dataInputStream.read(buffer);
      bytesRead = bytesRead == -1 ? buffer.length : bytesRead;

      // Close socket after reading
      dataInputStream.close();
      dataOutputStream.close();
      socket.close();

      // 0x4e = ProtocolAck
      if (buffer[0] != 0x4e) {
        return false;
      }

      // Hostname size, Big Endian
      int hostnameOffset = 3;
      int hostnameSize = ((buffer[1] & 0xFF) << 8 | (buffer[2] & 0xFF)) & 0xFFFF;

      // +2 for 2 null byte
      // +2 for 2 bytes for the port
      if (hostnameOffset + hostnameSize + 2 + 2 > bytesRead) {
        logger.atWarning().log("Data exceeds buffer size");
        return false;
      }

      // Check for 2 null bytes after hostname
      if (buffer[hostnameOffset + hostnameSize] != 0x00
          || buffer[hostnameOffset + hostnameSize + 1] != 0x00) {
        return false;
      }

      // Parse client host
      byte[] hostBytes =
          Arrays.copyOfRange(buffer, hostnameOffset, hostnameOffset + hostnameSize);
      String clientHost = new String(hostBytes, StandardCharsets.UTF_8);
      if (!clientHost.matches("[\\w:._-]+")) {
        logger.atWarning().log("Invalid client host string");
        return false;
      }

      logger.atInfo().log("RMI server detected");
      return true;
    } catch (IOException e) {
      return false;
    }
  }
}
