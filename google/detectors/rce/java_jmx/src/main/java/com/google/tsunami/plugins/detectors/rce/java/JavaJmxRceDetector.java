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
import java.net.MalformedURLException;
import java.time.Clock;
import java.time.Instant;
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
                .filter(JavaJmxRceDetector::isRmiOrUnknownService)
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
   * which isn't high enough to detect Java RMI services. Therefore we run this detector for
   * "java-rmi" services as well as network service whose service name is empty.
   */
  private static boolean isRmiOrUnknownService(NetworkService networkService) {
    return networkService.getServiceName().isEmpty()
        || NetworkServiceUtils.getServiceName(networkService).equals("java-rmi");
  }
}
