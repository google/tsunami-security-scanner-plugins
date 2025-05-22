/*
 * Copyright 2022 Google LLC
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
package com.google.tsunami.plugins.detectors.cves.cve202323752;

import static com.google.common.truth.extensions.proto.ProtoTruth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostnameAndPort;

import com.google.common.collect.ImmutableList;
import com.google.inject.Guice;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.common.net.http.HttpStatus;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.common.time.testing.FakeUtcClockModule;
import com.google.tsunami.proto.AdditionalDetail;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.Software;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.TextData;
import com.google.tsunami.proto.TransportProtocol;
import com.google.tsunami.proto.Vulnerability;
import com.google.tsunami.proto.VulnerabilityId;
import java.io.IOException;
import java.time.Instant;
import javax.inject.Inject;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class Cve202323752VulnDetectorTest {

  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2020-01-01T00:00:00.00Z"));

  @Inject private Cve202323752VulnDetector detector;

  private final MockWebServer mockWebServer = new MockWebServer();

  private NetworkService joomlaService;
  private static final String LEAKED_DATA_JSON_SAMPLE =
      "{\n"
          + "    \"data\": [\n"
          + "        {\n"
          + "            \"type\": \"application\",\n"
          + "            \"id\": \"224\",\n"
          + "            \"attributes\": {\n"
          + "                \"host\": \"google.com\",\n"
          + "                \"id\": 224\n"
          + "            }\n"
          + "        },\n"
          + "        {\n"
          + "            \"type\": \"application\",\n"
          + "            \"id\": \"224\",\n"
          + "            \"attributes\": {\n"
          + "                \"user\": \"root\",\n"
          + "                \"id\": 224\n"
          + "            }\n"
          + "        },\n"
          + "        {\n"
          + "            \"type\": \"application\",\n"
          + "            \"id\": \"224\",\n"
          + "            \"attributes\": {\n"
          + "                \"password\": \"example\",\n"
          + "                \"id\": 224\n"
          + "            }\n"
          + "        }\n"
          + "    ]\n"
          + "}";
  private TargetInfo targetInfo;

  @Before
  public void setUp() throws IOException {
    mockWebServer.start();
    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new HttpClientModule.Builder().build(),
            new Cve202323752DetectorBootstrapModule())
        .injectMembers(this);

    joomlaService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .setTransportProtocol(TransportProtocol.TCP)
            .setSoftware(Software.newBuilder().setName("joomla 4.2.6-php8.0"))
            .setServiceName("http")
            .build();

    targetInfo =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .build();
  }

  @After
  public void tearDown() throws IOException {
    mockWebServer.shutdown();
  }

  final Dispatcher dispatcher =
      new Dispatcher() {

        @Override
        public MockResponse dispatch(RecordedRequest request) throws InterruptedException {
          if (request.getPath().equals("/api/index.php/v1/config/application?public=true")) {
            return new MockResponse()
                .addHeader("Content-Type", "application/json; charset=utf-8")
                .setBody(LEAKED_DATA_JSON_SAMPLE)
                .setResponseCode(HttpStatus.OK.code());
          }
          return new MockResponse().setResponseCode(404);
        }
      };

  @Test
  public void detect_whenVulnerable_returnsVulnerability() {
    mockWebServer.setDispatcher(dispatcher);
    DetectionReportList mockWebServerDetectionReports =
        detector.detect(targetInfo, ImmutableList.of(joomlaService));

    // all we need to check is Detection Status But I think it is very hard to set the
    // addAdditionalDetails , so I add the original Report addAdditionalDetails here in
    // expected and then check for AdditionalDetails in another assert
    DetectionReport expectedDetectionReport =
        DetectionReport.newBuilder()
            .setTargetInfo(targetInfo)
            .setNetworkService(joomlaService)
            .setDetectionTimestamp(Timestamps.fromMillis(Instant.now(fakeUtcClock).toEpochMilli()))
            .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
            .setVulnerability(
                Vulnerability.newBuilder()
                    .setMainId(
                        VulnerabilityId.newBuilder()
                            .setPublisher("TSUNAMI_COMMUNITY")
                            .setValue("CVE_2023_23752"))
                    .addRelatedId(
                        VulnerabilityId.newBuilder()
                            .setPublisher("CVE")
                            .setValue("CVE-2023-23752"))
                    .setSeverity(Severity.HIGH)
                    .setTitle("Joomla unauthorized access to webservice endpoints")
                    .setDescription(
                        "CVE-2023-23752: An improper access check allows unauthorized access to"
                            + " webservice endpoints. attacker can get the host address "
                            + "and username and password of the configured joomla database.")
                    .setRecommendation("Upgrade Joomla to 4.2.8 and above versions.")
                    .addAdditionalDetails(
                        AdditionalDetail.newBuilder()
                            .setTextData(TextData.newBuilder().setText(LEAKED_DATA_JSON_SAMPLE))))
            .build();

    // Vulnerable to CVE202323752
    assertThat(mockWebServerDetectionReports.getDetectionReportsList())
        .containsExactly(expectedDetectionReport);
  }

  @Test
  public void detect_whenNotVulnerable_returnsNoVulnerability() {
    mockWebServer.url("/notexistpath");
    MockResponse response =
        new MockResponse()
            .addHeader("Content-Type", "application/json; charset=utf-8")
            .setBody("NotExistDetectionString")
            .setResponseCode(200);
    mockWebServer.enqueue(response);

    DetectionReportList mockWebServerDetectionReports =
        detector.detect(targetInfo, ImmutableList.of(joomlaService));
    assertThat(mockWebServerDetectionReports.getDetectionReportsList()).isEmpty();
  }
}
