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

package com.google.tsunami.plugins.rce.dolphinscheduler;

import static com.google.common.truth.Truth.assertThat;

import com.google.common.collect.ImmutableList;
import com.google.inject.Guice;
import com.google.tsunami.common.data.NetworkEndpointUtils;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.common.net.http.HttpStatus;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.common.time.testing.FakeUtcClockModule;
import com.google.tsunami.plugin.payload.testing.FakePayloadGeneratorModule;
import com.google.tsunami.plugin.payload.testing.PayloadTestHelper;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.TransportProtocol;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import javax.inject.Inject;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link ApacheDolphinSchedulerExposedJavaGatewayDetector}. */
@RunWith(JUnit4.class)
public final class ApacheDolphinSchedulerExposedJavaGatewayDetectorTest {
  private static final String DOLPHINSCHEDULER_PAGE_CONTENT =
      "<html><head><title>DolphinScheduler</title></head><body>Apache"
          + " DolphinScheduler</body></html>";

  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2025-02-20T00:00:00.00Z"));

  private MockWebServer mockWebServer;
  private MockWebServer mockCallbackServer;
  private MockPy4jServer mockPy4jServer;
  private ExecutorService executor;
  private NetworkService service;
  private TargetInfo targetInfo;

  @Inject private ApacheDolphinSchedulerExposedJavaGatewayDetector detector;

  @Before
  public void setUp() throws IOException {
    mockWebServer = new MockWebServer();
    mockWebServer.start();
    mockCallbackServer = new MockWebServer();
    mockCallbackServer.start();
    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new HttpClientModule.Builder().build(),
            FakePayloadGeneratorModule.builder().setCallbackServer(mockCallbackServer).build(),
            new ApacheDolphinSchedulerExposedJavaGatewayDetectorModule())
        .injectMembers(this);

    targetInfo =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(NetworkEndpointUtils.forHostname(mockWebServer.getHostName()))
            .build();
    service =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                NetworkEndpointUtils.forHostnameAndPort(
                    mockWebServer.getHostName(), mockWebServer.getPort()))
            .setTransportProtocol(TransportProtocol.TCP)
            .setServiceName("http")
            .build();
    executor = Executors.newSingleThreadExecutor();
  }

  @After
  public void tearDown() throws Exception {
    if (mockWebServer != null) {
      mockWebServer.shutdown();
    }
    if (mockCallbackServer != null) {
      mockCallbackServer.shutdown();
    }
    if (mockPy4jServer != null) {
      mockPy4jServer.close();
    }
    if (executor != null) {
      executor.shutdown();
    }
  }

  @Test
  public void detect_whenNotDolphinScheduler_returnsNoVulnerability() throws IOException {
    // Enqueue responses for all fingerprinting paths: "", "dolphinscheduler",
    // "dolphinscheduler/ui", "dolphinscheduler/ui/login"
    for (int i = 0; i < 4; i++) {
      mockWebServer.enqueue(
          new MockResponse()
              .setResponseCode(HttpStatus.OK.code())
              .setBody("Some other application content"));
    }

    DetectionReportList detectionReports = detector.detect(targetInfo, ImmutableList.of(service));

    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
  }

  @Test
  public void detect_whenDolphinSchedulerButNoJavaGateway_returnsNoVulnerability()
      throws IOException {
    // Enqueue responses for all fingerprinting paths: "", "dolphinscheduler",
    // "dolphinscheduler/ui", "dolphinscheduler/ui/login"
    for (int i = 0; i < 4; i++) {
      mockWebServer.enqueue(
          new MockResponse()
              .setResponseCode(HttpStatus.OK.code())
              .setBody(DOLPHINSCHEDULER_PAGE_CONTENT));
    }

    // No mock Py4j server - connection to host:25333 will fail
    DetectionReportList detectionReports = detector.detect(targetInfo, ImmutableList.of(service));
    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
  }

  @Test
  public void detect_whenDolphinSchedulerWithExposedJavaGateway_reportsVulnerability()
      throws Exception {
    // Enqueue responses for all fingerprinting paths: "", "dolphinscheduler",
    // "dolphinscheduler/ui", "dolphinscheduler/ui/login"
    for (int i = 0; i < 4; i++) {
      mockWebServer.enqueue(
          new MockResponse()
              .setResponseCode(HttpStatus.OK.code())
              .setBody(DOLPHINSCHEDULER_PAGE_CONTENT));
    }

    mockCallbackServer.enqueue(PayloadTestHelper.generateMockSuccessfulCallbackResponse());

    // Use port 25333 if available, otherwise skip this test
    mockPy4jServer = new MockPy4jServer(true);
    try {
      mockPy4jServer.start(25333);
    } catch (IOException e) {
      // Port 25333 might be in use, skip test
      org.junit.Assume.assumeNoException("Port 25333 not available for test", e);
    }
    executor.submit(mockPy4jServer);
    mockPy4jServer.waitUntilReady();

    try {
      DetectionReportList detectionReports = detector.detect(targetInfo, ImmutableList.of(service));

      assertThat(detectionReports.getDetectionReportsList()).hasSize(1);
      DetectionReport report = detectionReports.getDetectionReports(0);
      assertThat(report.getDetectionStatus()).isEqualTo(DetectionStatus.VULNERABILITY_VERIFIED);
      assertThat(report.getNetworkService()).isEqualTo(service);
      assertThat(report.getVulnerability().getMainId().getValue())
          .isEqualTo("DOLPHINSCHEDULER_EXPOSED_JAVA_GATEWAY");
    } finally {
      mockPy4jServer.close();
    }
  }

  @Test
  public void getAdvisories_returnsExpectedAdvisory() {
    var advisories = detector.getAdvisories();

    assertThat(advisories).hasSize(1);
    assertThat(advisories.get(0).getMainId().getPublisher()).isEqualTo("TSUNAMI_COMMUNITY");
    assertThat(advisories.get(0).getMainId().getValue())
        .isEqualTo("DOLPHINSCHEDULER_EXPOSED_JAVA_GATEWAY");
    assertThat(advisories.get(0).getSeverity())
        .isEqualTo(com.google.tsunami.proto.Severity.CRITICAL);
  }

  /**
   * A mock Py4j server that handles the full runShellScript protocol: auth, reflection (get Runtime
   * class), getRuntime(), and exec(script). Instead of actually executing the payload, it returns a
   * success response as if it was executed. This ensures the callback response stays queued for the
   * polling request from payload.checkIfExecuted(), avoiding the race where the RCE execution
   * consumes the response before the poll.
   */
  private static class MockPy4jServer implements Runnable {
    private final boolean acceptAuth;
    private ServerSocket serverSocket;
    private volatile boolean ready;
    private int port = 25333;

    MockPy4jServer(boolean acceptAuth) {
      this.acceptAuth = acceptAuth;
    }

    void start(int port) throws IOException {
      this.port = port;
      this.serverSocket = new ServerSocket();
      this.serverSocket.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), port));
    }

    int getPort() {
      return serverSocket != null ? serverSocket.getLocalPort() : port;
    }

    void waitUntilReady() throws InterruptedException {
      for (int i = 0; i < 50; i++) {
        if (ready) return;
        Thread.sleep(100);
      }
    }

    void close() throws IOException {
      if (serverSocket != null && !serverSocket.isClosed()) {
        serverSocket.close();
      }
    }

    @Override
    public void run() {
      try {
        if (serverSocket == null) {
          serverSocket = new ServerSocket(0, 0, InetAddress.getLoopbackAddress());
        }
        ready = true;
        while (!serverSocket.isClosed()) {
          try (Socket client = serverSocket.accept()) {
            BufferedReader reader =
                new BufferedReader(
                    new InputStreamReader(client.getInputStream(), StandardCharsets.UTF_8));
            PrintWriter writer =
                new PrintWriter(
                    new OutputStreamWriter(client.getOutputStream(), StandardCharsets.UTF_8));

            while (true) {
              String line = reader.readLine();
              if (line == null) break;

              // Auth command: A -> token (no "e" - Py4j auth doesn't use end marker)
              if ("A".equals(line)) {
                String token = reader.readLine();
                if (acceptAuth
                    && ApacheDolphinSchedulerExposedJavaGatewayDetector.DEFAULT_AUTH_TOKEN.equals(
                        token)) {
                  writer.write("!yv\n");
                } else {
                  writer.write("!xsBad auth token\n");
                }
                writer.flush();
                continue;
              }

              // Reflection: r -> c -> java.lang.Runtime -> e
              if ("r".equals(line)) {
                String sub = reader.readLine();
                String fqn = reader.readLine();
                reader.readLine(); // consume e
                if ("c".equals(sub) && "java.lang.Runtime".equals(fqn)) {
                  writer.write("!yr0\n");
                } else {
                  writer.write("!xn\n");
                }
                writer.flush();
                continue;
              }

              // Call command: targetId -> methodName -> [args] -> e
              if ("c".equals(line)) {
                String targetId = reader.readLine();
                String methodName = reader.readLine();
                String argLine = reader.readLine();
                while (argLine != null && !argLine.isEmpty() && !"e".equals(argLine)) {
                  argLine = reader.readLine();
                }
                // Return success as if exec was executed, without actually running the payload.
                // The callback response remains queued for payload.checkIfExecuted() to consume.
                writer.write("!yr1\n");
                writer.flush();
              }
            }
          }
        }
      } catch (IOException e) {
        // Ignore - socket closed
      }
    }
  }
}
