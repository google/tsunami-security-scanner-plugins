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
package com.google.tsunami.plugins.papercut;

import static com.google.common.truth.extensions.proto.ProtoTruth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostnameAndPort;
import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.common.collect.ImmutableList;
import com.google.common.io.Resources;
import com.google.inject.Guice;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.common.time.testing.FakeUtcClockModule;
import com.google.tsunami.plugin.payload.testing.FakePayloadGeneratorModule;
import com.google.tsunami.plugins.detectors.vmwareairaoperationsforlogsRceDetectorBootstrapModule;
import com.google.tsunami.plugins.detectors.vmwareairaoperationsforlogsVulnDetector;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.Software;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.TransportProtocol;
import com.google.tsunami.proto.Vulnerability;
import com.google.tsunami.proto.VulnerabilityId;
import java.io.IOException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Arrays;
import javax.inject.Inject;
import okhttp3.Headers;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link vmwareairaoperationsforlogsVulnDetector}. */
@RunWith(JUnit4.class)
public final class VmwareAiraOperationForLogsVulnDetectorTest {

  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2020-01-01T00:00:00.00Z"));
  private final SecureRandom testSecureRandom =
      new SecureRandom() {
        @Override
        public void nextBytes(byte[] bytes) {
          Arrays.fill(bytes, (byte) 0xFF);
        }
      };
  private final MockWebServer mockWebServer = new MockWebServer();
  private final MockWebServer mockCallbackServer = new MockWebServer();
  private NetworkService vmwareairaoperationforlogsService;
  @Inject private vmwareairaoperationsforlogsVulnDetector detector;
  private DetectionReport detectorReport;
  private TargetInfo targetInfo;

  // Helper function load additional resources used in the tests
  private static String loadResource(String file) throws IOException {
    return Resources.toString(
        Resources.getResource(VmwareAiraOperationForLogsVulnDetectorTest.class, file), UTF_8);
  }

  @Before
  public void setUp() throws IOException {
    mockWebServer.start();
    mockCallbackServer.start();

    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new HttpClientModule.Builder().build(),
            FakePayloadGeneratorModule.builder().setCallbackServer(mockCallbackServer).build(),
            new vmwareairaoperationsforlogsRceDetectorBootstrapModule())
        .injectMembers(this);

    vmwareairaoperationforlogsService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .setTransportProtocol(TransportProtocol.TCP)
            .setSoftware(Software.newBuilder().setName("vmware aira operation for logs"))
            .setServiceName("http")
            .build();

    targetInfo =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(vmwareairaoperationforlogsService.getNetworkEndpoint())
            .build();

    detectorReport =
        DetectionReport.newBuilder()
            .setTargetInfo(targetInfo)
            .setNetworkService(vmwareairaoperationforlogsService)
            .setDetectionTimestamp(Timestamps.fromMillis(Instant.now(fakeUtcClock).toEpochMilli()))
            .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
            .setVulnerability(
                Vulnerability.newBuilder()
                    .setMainId(
                        VulnerabilityId.newBuilder()
                            .setPublisher("TSUNAMI_COMMUNITY")
                            .setValue("CVE-2023-20864"))
                    .setSeverity(Severity.CRITICAL)
                    .setTitle("vmware aira operations for logs RCE")
                    .setDescription(
                        "VMware Aria Operations for Logs contains a deserialization vulnerability. An unauthenticated, "
                            + "malicious actor with network access to VMware Aria Operations for Logs may be able to"
                            + " execute arbitrary code as root.\n"
                            + "The affected version is 8.10.2, it is recommended to upgrade to 8.12")
                    .setRecommendation(
                        "Update to versions that are at least 8.12.0 or any later" + " version."))
            .build();
  }

  @After
  public void tearDown() throws Exception {
    mockWebServer.shutdown();
    mockCallbackServer.shutdown();
  }

  @Test
  public void detect_whenVulnerable_returnsVulnerability() throws IOException {
    Headers.Builder headerBuilder = new Headers.Builder();
    Headers jsessionHeader =
        headerBuilder
            .set(
                "Set-Cookie",
                "JSESSIONID=80C859065CFD9FCB2CF1CC5B64EDCFEF; "
                    + "cs=1BE15158783FD8202BBF3EB78C901DD9; Secure; HttpOnly; SameSite=None")
            .set(
                "X-CSRF-Token",
                "MzExNUZDQThCNkI5RDlENThDNjlCMTY0MTdENURCNzMwMDAwMDE4ZjliNDc1ZDc588D1AtMtOhDOHlXLw_wDuJqM_HUppnYTBSvSAP6qELM=")
            .build();

    mockWebServer.url("/csrf");

    mockWebServer.enqueue(
        new MockResponse()
            .setResponseCode(200)
            .setHeaders(jsessionHeader)
            .setBody("{\"succ\":true}"));

    mockWebServer.url("/api/v2/internal/cluster/applyMembership");

    mockWebServer.enqueue(
        new MockResponse()
            .setResponseCode(500)
            .setBody("{\"errorMessage\":\"Internal error occurred during request processing.\"}"));

    DetectionReportList detectionReportList =
        detector.detect(targetInfo, ImmutableList.of(vmwareairaoperationforlogsService));

    assertThat(detectionReportList.getDetectionReportsList()).containsExactly(detectorReport);
  }

  @Test
  public void detect_whenNotVulnerable_returnsNoFinding() throws IOException {

    // Set up the mock webserver
    //  - Redirects to a login page

    Headers.Builder headerBuilder = new Headers.Builder();

    Headers jsessionHeader =
        headerBuilder
            .set(
                "Set-Cookie",
                "JSESSIONID=80C859065CFD9FCB2CF1CC5B64EDCFEF; cs=1BE15158783FD8202BBF3EB78C901DD9; Secure; HttpOnly; SameSite=None")
            .set(
                "X-CSRF-Token",
                "MzExNUZDQThCNkI5RDlENThDNjlCMTY0MTdENURCNzMwMDAwMDE4ZjliNDc1ZDc588D1AtMtOhDOHlXLw_wDuJqM_HUppnYTBSvSAP6qELM=")
            .build();

    mockWebServer.url("/csrf");

    mockWebServer.enqueue(
        new MockResponse()
            .setResponseCode(200)
            .setHeaders(jsessionHeader)
            .setBody("{\"succ\":true}"));

    mockWebServer.url("/api/v2/internal/cluster/applyMembership");

    mockWebServer.enqueue(
        new MockResponse()
            .setResponseCode(404)
            .setBody(
                "{\"errorMessage\":\"Handler not found for request POST /api/v2/internal/cluster/applyMembership\"}"));
    // Load the login page
    mockWebServer.enqueue(
        new MockResponse()
            .setResponseCode(400)
            .setBody(
                "java.io.InvalidClassException: Class name not accepted: java.util.PriorityQueue"));

    assertThat(
            detector
                .detect(targetInfo, ImmutableList.of(vmwareairaoperationforlogsService))
                .getDetectionReportsList())
        .isEmpty();
  }
}
