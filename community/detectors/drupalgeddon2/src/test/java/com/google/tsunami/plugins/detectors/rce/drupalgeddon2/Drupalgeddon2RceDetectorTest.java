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
package com.google.tsunami.plugins.detectors.rce.drupalgeddon2;

import static com.google.common.truth.extensions.proto.ProtoTruth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostname;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostnameAndPort;

import com.google.common.collect.ImmutableList;
import com.google.inject.Guice;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.common.net.http.HttpStatus;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.common.time.testing.FakeUtcClockModule;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.TransportProtocol;
import com.google.tsunami.proto.Vulnerability;
import com.google.tsunami.proto.VulnerabilityId;
import java.io.IOException;
import java.time.Instant;
import java.util.stream.Stream;
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

/** Unit tests for {@link Drupalgeddon2RceDetector}. */
@RunWith(JUnit4.class)
public final class Drupalgeddon2RceDetectorTest {
  private static final String FORM_BUILD_ID = "form-UxVoDS2YJ--T_ws0_gEyJT3jsZstGSUCPU1XaXZEvTE";
  private static final String DEFAULT_HEAD_PARTLY_V7 =
      "...<meta name=\"Generator\" content=\"Drupal 7 (http://drupal.org)\" />...";
  private static final String DEFAULT_HEAD_PARTLY_V8 =
      "...<meta name=\"Generator\" content=\"Drupal 8 (https://www.drupal.org)\" />...";
  private static final String DEFAULT_BODY_PARTLY_V7 =
      "...<input type=\"hidden\" name=\"form_build_id\" value=\"" + FORM_BUILD_ID + "\" />...";
  private static final String VULN_FORM_PATH_V7 = "user/password";
  private static final String VULN_FORM_PATH_V8 = "user/register";
  private static final String X_GENERATOR_HEADER_V7 = "Drupal 7 (http://drupal.org)";
  private static final String X_GENERATOR_HEADER_V8 = "Drupal 8 (https://www.drupal.org)";
  private static String fakeRandomString;

  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2020-01-01T00:00:00.00Z"));

  private MockWebServer mockWebServer;

  @Inject private Drupalgeddon2RceDetector detector;

  @Before
  public void setUp() throws IOException {
    mockWebServer = new MockWebServer();
    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new HttpClientModule.Builder().build(),
            new Drupalgeddon2RceDetectorBootstrapModule())
        .injectMembers(this);
  }

  @After
  public void tearDown() throws IOException {
    mockWebServer.shutdown();
  }

  public void detect_whenVulnerable_returnsVulnerability(
      Integer drupalVersion, Boolean skipChangeLog) throws Exception {
    mockWebServer.setDispatcher(
        drupalVersion == 7
            ? new VulnerableEndpointD7Dispatcher(skipChangeLog)
            : new VulnerableEndpointD8Dispatcher(skipChangeLog));

    NetworkService service =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .setTransportProtocol(TransportProtocol.TCP)
            .setServiceName("http")
            .build();

    TargetInfo targetInfo =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(forHostname(mockWebServer.getHostName()))
            .build();

    DetectionReportList detectionReports = detector.detect(targetInfo, ImmutableList.of(service));

    assertThat(detectionReports.getDetectionReportsList())
        .containsExactly(
            DetectionReport.newBuilder()
                .setTargetInfo(targetInfo)
                .setNetworkService(service)
                .setDetectionTimestamp(
                    Timestamps.fromMillis(Instant.now(fakeUtcClock).toEpochMilli()))
                .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
                .setVulnerability(
                    Vulnerability.newBuilder()
                        .setMainId(
                            VulnerabilityId.newBuilder()
                                .setPublisher("yuradoc")
                                .setValue("CVE-2018-7600"))
                        .setSeverity(Severity.CRITICAL)
                        .setTitle(
                            "Drupal RCE named Drupalgeddon2 (CVE-2018-7600) (SA-CORE-2018-002)")
                        .setDescription(
                            "Drupal before 7.58, 8.x before 8.3.9, 8.4.x before 8.4.6, "
                                + "and 8.5.x before 8.5.1 allows remote attackers to"
                                + " execute arbitrary code because of an issue affecting"
                                + " multiple subsystems with default or common module configurations."))
                .build());
  }

  @Test
  public void detect_whenVulnerable_D7_returnsVulnerability() throws Exception {
    mockWebServer.start();
    detect_whenVulnerable_returnsVulnerability(7, false);
    detect_whenVulnerable_returnsVulnerability(7, true);
  }

  @Test
  public void detect_whenVulnerable_D8_returnsVulnerability() throws Exception {
    detect_whenVulnerable_returnsVulnerability(8, false);
    detect_whenVulnerable_returnsVulnerability(8, true);
  }

  public void detect_whenNoVulnerable_D7_returnsVulnerability(Integer stopStep) throws Exception {
    mockWebServer.setDispatcher(new NoVulnerableEndpointD7Dispatcher(stopStep));
    mockWebServer.start();

    NetworkService service =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .setTransportProtocol(TransportProtocol.TCP)
            .setServiceName("http")
            .build();

    TargetInfo targetInfo =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(forHostname(mockWebServer.getHostName()))
            .build();

    DetectionReportList detectionReports = detector.detect(targetInfo, ImmutableList.of(service));

    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
  }

  @Test
  public void detect_whenNoVulnerable_D7_returnsVulnerability_stopStep0() throws Exception {
    detect_whenNoVulnerable_D7_returnsVulnerability(0);
  }

  @Test
  public void detect_whenNoVulnerable_D7_returnsVulnerability_stopStep1() throws Exception {
    detect_whenNoVulnerable_D7_returnsVulnerability(1);
  }

  public void detect_whenNoVulnerable_D8_returnsVulnerability(Boolean cleanUrl) throws Exception {
    mockWebServer.setDispatcher(new NoVulnerableEndpointD8Dispatcher(cleanUrl));
    mockWebServer.start();

    NetworkService service =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .setTransportProtocol(TransportProtocol.TCP)
            .setServiceName("http")
            .build();

    TargetInfo targetInfo =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(forHostname(mockWebServer.getHostName()))
            .build();

    DetectionReportList detectionReports = detector.detect(targetInfo, ImmutableList.of(service));

    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
  }

  @Test
  public void detect_whenNoVulnerable_D8_returnsVulnerability_cleanUrl() throws Exception {
    detect_whenNoVulnerable_D8_returnsVulnerability(true);
  }

  @Test
  public void detect_whenNoVulnerable_D8_returnsVulnerability_cleanUrlDisabled() throws Exception {
    detect_whenNoVulnerable_D8_returnsVulnerability(false);
  }

  private static final class VulnerableEndpointD7Dispatcher extends Dispatcher {

    private final Boolean skipChangeLog;

    VulnerableEndpointD7Dispatcher(Boolean skipChangeLog) {
      this.skipChangeLog = skipChangeLog;
    }

    @Override
    public MockResponse dispatch(RecordedRequest recordedRequest) {
      if (!this.skipChangeLog && recordedRequest.getPath().equals("/CHANGELOG.txt"))
        return new MockResponse()
            .setHeader("X-Generator", X_GENERATOR_HEADER_V7)
            .setResponseCode(HttpStatus.OK.code())
            .setBody("Drupal 7.57,...");
      else if (Stream.of("/includes/bootstrap.inc", "/includes/database.inc")
          .anyMatch(s -> recordedRequest.getPath().equals(s)))
        return new MockResponse().setResponseCode(HttpStatus.FORBIDDEN.code());
      else if (recordedRequest.getPath().endsWith(VULN_FORM_PATH_V7)
          || recordedRequest.getPath().equals("/"))
        return new MockResponse()
            .setHeader("X-Generator", X_GENERATOR_HEADER_V7)
            .setResponseCode(HttpStatus.OK.code())
            .setBody(DEFAULT_HEAD_PARTLY_V7 + DEFAULT_BODY_PARTLY_V7);
      else if (recordedRequest.getPath().contains(VULN_FORM_PATH_V7)) {
        String payloadCmd = "echo%20";
        fakeRandomString =
            recordedRequest
                .getPath()
                .substring(recordedRequest.getPath().lastIndexOf(payloadCmd) + payloadCmd.length());
        return new MockResponse()
            .setHeader("X-Generator", X_GENERATOR_HEADER_V7)
            .setResponseCode(HttpStatus.OK.code())
            .setBody(DEFAULT_BODY_PARTLY_V7);
      } else if (recordedRequest.getPath().endsWith("file/ajax/name/%23value/" + FORM_BUILD_ID))
        return new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody(fakeRandomString);
      return new MockResponse()
          .setResponseCode(HttpStatus.NOT_FOUND.code())
          .setBody(DEFAULT_HEAD_PARTLY_V7);
    }
  }

  private static final class VulnerableEndpointD8Dispatcher extends Dispatcher {

    private final Boolean skipChangeLog;

    VulnerableEndpointD8Dispatcher(Boolean skipChangeLog) {
      this.skipChangeLog = skipChangeLog;
    }

    @Override
    public MockResponse dispatch(RecordedRequest recordedRequest) {
      if (!this.skipChangeLog && recordedRequest.getPath().equals("/core/CHANGELOG.txt"))
        return new MockResponse()
            .setHeader("X-Generator", X_GENERATOR_HEADER_V8)
            .setResponseCode(HttpStatus.OK.code())
            .setBody("Drupal 8.0.6,...");
      else if (recordedRequest.getPath().equals("/core/includes/bootstrap.inc"))
        return new MockResponse().setResponseCode(HttpStatus.FORBIDDEN.code());
      else if (recordedRequest.getPath().endsWith(VULN_FORM_PATH_V8)
          || recordedRequest.getPath().equals("/"))
        return new MockResponse()
            .setHeader("X-Generator", X_GENERATOR_HEADER_V8)
            .setResponseCode(HttpStatus.OK.code())
            .setBody(DEFAULT_HEAD_PARTLY_V8);
      else if (recordedRequest.getPath().contains(VULN_FORM_PATH_V8)) {
        String payloadCmd = "echo ";
        fakeRandomString = recordedRequest.getBody().readUtf8();
        fakeRandomString =
            fakeRandomString.substring(
                fakeRandomString.lastIndexOf(payloadCmd) + payloadCmd.length());
        return new MockResponse()
            .setHeader("X-Generator", X_GENERATOR_HEADER_V8)
            .setResponseCode(HttpStatus.OK.code())
            .setBody(fakeRandomString + "...");
      }
      return new MockResponse()
          .setResponseCode(HttpStatus.NOT_FOUND.code())
          .setBody(DEFAULT_HEAD_PARTLY_V8);
    }
  }

  private static final class NoVulnerableEndpointD7Dispatcher extends Dispatcher {

    private final Integer stopStep;

    NoVulnerableEndpointD7Dispatcher(Integer stopStep) {
      this.stopStep = stopStep;
    }

    NoVulnerableEndpointD7Dispatcher() {
      this(0);
    }

    @Override
    public MockResponse dispatch(RecordedRequest recordedRequest) {
      if (recordedRequest.getPath().equals("/CHANGELOG.txt"))
        return new MockResponse()
            .setHeader("X-Generator", X_GENERATOR_HEADER_V7)
            .setResponseCode(HttpStatus.OK.code())
            .setBody("Drupal 7.82,...");
      else if (Stream.of("/includes/bootstrap.inc", "/includes/database.inc")
          .anyMatch(s -> recordedRequest.getPath().equals(s)))
        return new MockResponse().setResponseCode(HttpStatus.FORBIDDEN.code());
      else if (recordedRequest.getPath().endsWith(VULN_FORM_PATH_V7)
          || recordedRequest.getPath().equals("/"))
        return new MockResponse()
            .setHeader("X-Generator", X_GENERATOR_HEADER_V7)
            .setResponseCode(HttpStatus.OK.code())
            .setBody(DEFAULT_HEAD_PARTLY_V7 + DEFAULT_BODY_PARTLY_V7);
      else if (recordedRequest.getPath().contains(VULN_FORM_PATH_V7)) {
        String payloadCmd = "echo%20";
        fakeRandomString =
            this.stopStep == 0
                ? recordedRequest
                    .getPath()
                    .substring(
                        recordedRequest.getPath().lastIndexOf(payloadCmd) + payloadCmd.length())
                : "_wrong_val_";
        return new MockResponse()
            .setHeader("X-Generator", X_GENERATOR_HEADER_V7)
            .setResponseCode(HttpStatus.OK.code())
            .setBody(this.stopStep == 0 ? "... ..." : DEFAULT_BODY_PARTLY_V7);
      } else if (recordedRequest.getPath().endsWith("file/ajax/name/%23value/" + FORM_BUILD_ID))
        return new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody(fakeRandomString);
      return new MockResponse()
          .setResponseCode(HttpStatus.NOT_FOUND.code())
          .setBody(DEFAULT_HEAD_PARTLY_V7);
    }
  }

  private static final class NoVulnerableEndpointD8Dispatcher extends Dispatcher {

    private Boolean cleanUrl;

    NoVulnerableEndpointD8Dispatcher(Boolean cleanUrl) {
      this.cleanUrl = cleanUrl;
    }

    NoVulnerableEndpointD8Dispatcher() {
      this(true);
    }

    @Override
    public MockResponse dispatch(RecordedRequest recordedRequest) {
      if (recordedRequest.getPath().equals("/core/CHANGELOG.txt"))
        return new MockResponse()
            .setHeader("X-Generator", X_GENERATOR_HEADER_V8)
            .setResponseCode(HttpStatus.OK.code())
            .setBody("Drupal 8.0.6,...");
      else if (recordedRequest.getPath().equals("/core/includes/bootstrap.inc"))
        return new MockResponse().setResponseCode(HttpStatus.FORBIDDEN.code());
      else if (!this.cleanUrl && recordedRequest.getPath().endsWith("/" + VULN_FORM_PATH_V8))
        return new MockResponse()
            .setResponseCode(HttpStatus.NOT_FOUND.code())
            .setBody(DEFAULT_HEAD_PARTLY_V8);
      else if (recordedRequest.getPath().endsWith(VULN_FORM_PATH_V8)
          || recordedRequest.getPath().equals("/"))
        return new MockResponse()
            .setHeader("X-Generator", X_GENERATOR_HEADER_V8)
            .setResponseCode(HttpStatus.OK.code())
            .setBody(DEFAULT_HEAD_PARTLY_V8);
      else if (recordedRequest.getPath().contains(VULN_FORM_PATH_V8)) {
        fakeRandomString = "_wrong_val_";
        return new MockResponse()
            .setHeader("X-Generator", X_GENERATOR_HEADER_V8)
            .setResponseCode(HttpStatus.OK.code())
            .setBody(fakeRandomString);
      }
      return new MockResponse()
          .setResponseCode(HttpStatus.NOT_FOUND.code())
          .setBody(DEFAULT_HEAD_PARTLY_V8);
    }
  }
}
