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

import static com.google.common.truth.extensions.proto.ProtoTruth.assertThat;

import com.google.common.collect.ImmutableList;
import com.google.inject.Guice;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkEndpointUtils;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.common.time.testing.FakeUtcClockModule;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.Vulnerability;
import com.google.tsunami.proto.VulnerabilityId;
import java.lang.management.ManagementFactory;
import java.rmi.registry.LocateRegistry;
import java.time.Instant;
import java.util.HashMap;
import javax.inject.Inject;
import javax.management.remote.JMXConnectorServer;
import javax.management.remote.JMXConnectorServerFactory;
import javax.management.remote.JMXServiceURL;
import javax.management.remote.rmi.RMIConnectorServer;
import javax.rmi.ssl.SslRMIClientSocketFactory;
import javax.rmi.ssl.SslRMIServerSocketFactory;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link JavaJmxRceDetector}. */
@RunWith(JUnit4.class)
public final class JavaJmxRceDetectorTest {
  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2020-01-01T00:00:00.00Z"));
  private static final int REGISTRY_PORT = 65535;

  private static JMXServiceURL url;
  private JMXConnectorServer server;

  @Inject private JavaJmxRceDetector detector;

  @BeforeClass
  public static void setUpClass() throws Exception {
    LocateRegistry.createRegistry(REGISTRY_PORT);
    url =
        new JMXServiceURL(String.format("service:jmx:rmi:///jndi/rmi://:%d/jmxrmi", REGISTRY_PORT));
  }

  @Before
  public void setUp() {
    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock), new JavaJmxRceDetectorBootstrapModule())
        .injectMembers(this);
  }

  @After
  public void tearDown() throws Exception {
    server.stop();
  }

  private void startVulnerableServer() throws Exception {
    server =
        JMXConnectorServerFactory.newJMXConnectorServer(
            url, null, ManagementFactory.getPlatformMBeanServer());
    server.start();
  }

  private void startSecureServer() throws Exception {
    HashMap<String, Object> env = new HashMap<>();

    SslRMIClientSocketFactory csf = new SslRMIClientSocketFactory();
    SslRMIServerSocketFactory ssf = new SslRMIServerSocketFactory();
    env.put(RMIConnectorServer.RMI_CLIENT_SOCKET_FACTORY_ATTRIBUTE, csf);
    env.put(RMIConnectorServer.RMI_SERVER_SOCKET_FACTORY_ATTRIBUTE, ssf);

    server =
        JMXConnectorServerFactory.newJMXConnectorServer(
            url, env, ManagementFactory.getPlatformMBeanServer());
    server.start();
  }

  @Test
  public void detect_whenJMXServiceRunningUnprotected_returnsVulnerability() throws Exception {
    startVulnerableServer();
    NetworkService vulnerableService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(NetworkEndpointUtils.forHostnameAndPort("localhost", REGISTRY_PORT))
            .build();

    DetectionReportList detectionReports =
        detector.detect(TargetInfo.getDefaultInstance(), ImmutableList.of(vulnerableService));

    assertThat(detectionReports.getDetectionReportsList())
        .containsExactly(
            DetectionReport.newBuilder()
                .setTargetInfo(TargetInfo.getDefaultInstance())
                .setNetworkService(vulnerableService)
                .setDetectionTimestamp(
                    Timestamps.fromMillis(Instant.now(fakeUtcClock).toEpochMilli()))
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
                            "Java Management Extension (JMX) allows remote monitoring and"
                                + " diagnostics for Java applications. Running JMX with"
                                + " unprotected RMI endpoint allows any remote users to create a"
                                + " javax.management.loading.MLet MBean and use it to create new"
                                + " MBeans from arbitrary URLs.")
                        .setRecommendation(
                            "Enable authentication and upgrade to the latest JDK environment."))
                .build());
  }

  @Test
  public void detect_whenJMXServiceRunningProtected_returnsEmptyDetectionReport() throws Exception {
    startSecureServer();
    NetworkService secureService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(NetworkEndpointUtils.forHostnameAndPort("localhost", REGISTRY_PORT))
            .build();

    DetectionReportList detectionReports =
        detector.detect(TargetInfo.getDefaultInstance(), ImmutableList.of(secureService));

    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
  }
}
