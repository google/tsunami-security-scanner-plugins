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
import static com.google.tsunami.common.data.NetworkEndpointUtils.*;
import static com.google.tsunami.plugins.detectors.cves.cve202323752.Cve202323752VulnDetector.DETECTION_STRING_BY_STATUS;
import static org.junit.Assert.*;

import com.google.common.collect.ImmutableList;
import com.google.inject.Guice;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.common.time.testing.FakeUtcClockModule;
import com.google.tsunami.proto.*;
import java.io.*;
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
  private static final String LeakedDataJsonSample =
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
          switch (request.getPath()) {
            case "/administrator/":
              return new MockResponse()
                  .addHeader(
                      "Set-Cookie",
                      "b0f43562296ae8185ebb20d3202668f1=0496c970e1c8176254a026e0e7348ba4; path=/; HttpOnly")
                  .setBody(
                      "<input type=\"hidden\" name=\"15d6ef4d0b0f035f892bb47aca7d5668\" value=\"1\"> \n"
                          + "<input type=\"hidden\" name=\"return\" value=\"aW5kZXgucGhw\"> \n")
                  .setResponseCode(200);
            case "/administrator/index.php":
              return new MockResponse()
                  .addHeader(
                      "Set-Cookie",
                      "0b1c5a17e16790c9e00e62288f3fdbd9=4e1c8abe0a7ded7b6d2f9c59834c0e61; path=/; HttpOnly")
                  .setResponseCode(200);
            case "/":
              return new MockResponse()
                  .addHeader(
                      "Set-Cookie",
                      "0b1c5a17e16790c9e00e62288f3fdbd9=4e1c8abe0a7ded7b6d2f9c59834c0e61; path=/; HttpOnly")
                  .setBody(
                      "<input type=\"hidden\" name=\"return\" value=\"aHR0cDovLzUxLjE5NS4yMTcuMTQ2OjgwMDAv\">\n"
                          + "\n"
                          + "<input type=\"hidden\" name=\"370a98fe1ced51f1b94513a39731cd3f\" value=\"1\">\n")
                  .setResponseCode(200);
            case "/index.php":
              return new MockResponse()
                  .addHeader(
                      "Set-Cookie",
                      "0b1c5a17e16790c9e00e62288f3fdbd9=25769e8b0373212a27a43ff32e08847d; path=/; HttpOnly")
                  .addHeader("Set-Cookie", "joomla_user_state=logged_in; path=/; HttpOnly")
                  .setResponseCode(303);
            case "/api/index.php/v1/config/application?public=true":
              return new MockResponse()
                  .addHeader("Content-Type", "application/json; charset=utf-8")
                  .setBody(LeakedDataJsonSample)
                  .setResponseCode(DETECTION_STRING_BY_STATUS);
          }
          return new MockResponse().setResponseCode(404);
        }
      };

  // this one won't set cookie on last request as the leaked credentials are invalid for
  // users/admins login
  final Dispatcher dispatcherNotReusedCredentials =
      new Dispatcher() {

        @Override
        public MockResponse dispatch(RecordedRequest request) throws InterruptedException {
          switch (request.getPath()) {
            case "/administrator/":
              return new MockResponse()
                  .addHeader(
                      "Set-Cookie",
                      "b0f43562296ae8185ebb20d3202668f1=0496c970e1c8176254a026e0e7348ba4; path=/; HttpOnly")
                  .setBody(
                      "<input type=\"hidden\" name=\"15d6ef4d0b0f035f892bb47aca7d5668\" value=\"1\"> \n"
                          + "<input type=\"hidden\" name=\"return\" value=\"aW5kZXgucGhw\"> \n")
                  .setResponseCode(200);
            case "/administrator/index.php":
              return new MockResponse().setResponseCode(303);
            case "/":
              return new MockResponse()
                  .addHeader(
                      "Set-Cookie",
                      "0b1c5a17e16790c9e00e62288f3fdbd9=4e1c8abe0a7ded7b6d2f9c59834c0e61; path=/; HttpOnly")
                  .setBody(
                      "<input type=\"hidden\" name=\"return\" value=\"aHR0cDovLzUxLjE5NS4yMTcuMTQ2OjgwMDAv\">\n"
                          + "\n"
                          + "<input type=\"hidden\" name=\"370a98fe1ced51f1b94513a39731cd3f\" value=\"1\">\n")
                  .setResponseCode(200);
            case "/index.php":
              return new MockResponse()
                  .addHeader(
                      "Set-Cookie",
                      "0b1c5a17e16790c9e00e62288f3fdbd9=25769e8b0373212a27a43ff32e08847d; path=/; HttpOnly")
                  .setResponseCode(303);
            case "/api/index.php/v1/config/application?public=true":
              return new MockResponse()
                  .addHeader("Content-Type", "application/json; charset=utf-8")
                  .setBody(LeakedDataJsonSample)
                  .setResponseCode(DETECTION_STRING_BY_STATUS);
          }
          return new MockResponse().setResponseCode(404);
        }
      };

  @Test
  public void DetectNotReusedLeakedCredentialsInLogin() {
    mockWebServer.setDispatcher(dispatcherNotReusedCredentials);
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
                    .setSeverity(Severity.CRITICAL)
                    .setTitle("Joomla unauthorized access to webservice endpoints")
                    .setDescription(
                        "CVE-2023-23752: An improper access check allows unauthorized access to"
                            + " webservice endpoints. attacker can get critical information of database and webserver like passwords by this vulnerability")
                    .setRecommendation("Upgrade to version 4.2.8 and higher")
                    .addAdditionalDetails(
                        AdditionalDetail.newBuilder()
                            .setTextData(
                                TextData.newBuilder()
                                    .setText(
                                        mockWebServerDetectionReports
                                            .getDetectionReports(0)
                                            .getVulnerability()
                                            .getAdditionalDetails(0)
                                            .getTextData()
                                            .getText()))))
            .build();

    // Vulnerable to CVE202323752
    assertThat(mockWebServerDetectionReports.getDetectionReportsList())
        .containsExactly(expectedDetectionReport);
    // Leaked Credentials have not been used as users/admins login credentials
    assertFalse(
        mockWebServerDetectionReports
            .getDetectionReports(0)
            .getVulnerability()
            .getAdditionalDetails(0)
            .getTextData()
            .getText()
            .contains("Scanner has checked the credentials against Administrator login page"));
  }

  @Test
  public void DetectReusedLeakedCredentialsInLogin() throws InterruptedException {
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
                    .setSeverity(Severity.CRITICAL)
                    .setTitle("Joomla unauthorized access to webservice endpoints")
                    .setDescription(
                        "CVE-2023-23752: An improper access check allows unauthorized access to"
                            + " webservice endpoints. attacker can get critical information of database and webserver like passwords by this vulnerability")
                    .setRecommendation("Upgrade to version 4.2.8 and higher")
                    .addAdditionalDetails(
                        AdditionalDetail.newBuilder()
                            .setTextData(
                                TextData.newBuilder()
                                    .setText(
                                        mockWebServerDetectionReports
                                            .getDetectionReports(0)
                                            .getVulnerability()
                                            .getAdditionalDetails(0)
                                            .getTextData()
                                            .getText()))))
            .build();

    // Vulnerable to CVE202323752
    assertThat(mockWebServerDetectionReports.getDetectionReportsList())
        .containsExactly(expectedDetectionReport);

    RecordedRequest request = mockWebServer.takeRequest();
    // get second request to check what kind of login attempt is this
    request = mockWebServer.takeRequest();
    if (request.getRequestUrl().toString().contains("administrator")) {
      assert (mockWebServerDetectionReports
              .getDetectionReports(0)
              .getVulnerability()
              .getAdditionalDetails(0)
              .getTextData()
              .getText())
          .contains("Scanner has checked the credentials against Administrator login page");

    } else {
      assert (mockWebServerDetectionReports
              .getDetectionReports(0)
              .getVulnerability()
              .getAdditionalDetails(0)
              .getTextData()
              .getText())
          .contains("Scanner has checked the credentials against Users login page");
    }
  }

  @Test
  public void DetectCVE202323752() {
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
                    .setSeverity(Severity.CRITICAL)
                    .setTitle("Joomla unauthorized access to webservice endpoints")
                    .setDescription(
                        "CVE-2023-23752: An improper access check allows unauthorized access to"
                            + " webservice endpoints. attacker can get critical information of database and webserver like passwords by this vulnerability")
                    .setRecommendation("Upgrade to version 4.2.8 and higher")
                    .addAdditionalDetails(
                        AdditionalDetail.newBuilder()
                            .setTextData(
                                TextData.newBuilder()
                                    .setText(
                                        mockWebServerDetectionReports
                                            .getDetectionReports(0)
                                            .getVulnerability()
                                            .getAdditionalDetails(0)
                                            .getTextData()
                                            .getText()))))
            .build();

    // Vulnerable to CVE202323752
    assertThat(mockWebServerDetectionReports.getDetectionReportsList())
        .containsExactly(expectedDetectionReport);

    // Double-Check the additional Data in report
    assert (mockWebServerDetectionReports
            .getDetectionReports(0)
            .getVulnerability()
            .getAdditionalDetails(0)
            .getTextData()
            .getText())
        .contains("The leaked credentials are: ");
  }

  @Test
  public void detect_publicExposedDataBaseHost() {
    mockWebServer.setDispatcher(dispatcher);
    DetectionReportList mockWebServerDetectionReports =
        detector.detect(targetInfo, ImmutableList.of(joomlaService));
    /*
    all we need to check is Detection Status But I think it is hard to set the
    addAdditionalDetails for expected detection report, so I add the original Report
    addAdditionalDetails here in
    expected and then check for AdditionalDetails in another assert
    */
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
                    .setSeverity(Severity.CRITICAL)
                    .setTitle("Joomla unauthorized access to webservice endpoints")
                    .setDescription(
                        "CVE-2023-23752: An improper access check allows unauthorized access to"
                            + " webservice endpoints. attacker can get critical information of database and webserver like passwords by this vulnerability")
                    .setRecommendation("Upgrade to version 4.2.8 and higher")
                    .addAdditionalDetails(
                        AdditionalDetail.newBuilder()
                            .setTextData(
                                TextData.newBuilder()
                                    .setText(
                                        mockWebServerDetectionReports
                                            .getDetectionReports(0)
                                            .getVulnerability()
                                            .getAdditionalDetails(0)
                                            .getTextData()
                                            .getText()))))
            .build();

    // Vulnerable to CVE202323752
    assertThat(mockWebServerDetectionReports.getDetectionReportsList())
        .containsExactly(expectedDetectionReport);

    // DataBase has a public IP address
    assert (mockWebServerDetectionReports
            .getDetectionReports(0)
            .getVulnerability()
            .getAdditionalDetails(0)
            .getTextData()
            .getText())
        .contains("it has a public IP address");
  }

  @Test
  public void detect_whenNotVulnerable_returnsNoVulnerability() {
    mockWebServer.url("/notexistpath123321");
    MockResponse response =
        new MockResponse()
            .addHeader("Content-Type", "application/json; charset=utf-8")
            .setBody("NotExistDetectionString")
            .setResponseCode(200);
    mockWebServer.enqueue(response);

    DetectionReportList mockWebServerDetectionReports =
        detector.detect(targetInfo, ImmutableList.of(joomlaService));
    assert (mockWebServerDetectionReports.getDetectionReportsList().isEmpty());
  }
}
