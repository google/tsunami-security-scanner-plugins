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
package com.google.tsunami.plugins.detectors.rce.tomcat.ghostcat;

import static com.google.common.truth.extensions.proto.ProtoTruth.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.when;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMultimap;
import com.google.inject.AbstractModule;
import com.google.inject.Guice;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.common.time.testing.FakeUtcClockModule;
import com.google.tsunami.plugins.detectors.rce.tomcat.ghostcat.ajp.AjpConnection;
import com.google.tsunami.plugins.detectors.rce.tomcat.ghostcat.ajp.AjpResponse;
import com.google.tsunami.proto.AdditionalDetail;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.TextData;
import com.google.tsunami.proto.Vulnerability;
import com.google.tsunami.proto.VulnerabilityId;
import java.io.IOException;
import java.time.Instant;
import javax.inject.Inject;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;

/** Unit tests for {@link GhostcatVulnDetector}. */
@RunWith(JUnit4.class)
public final class GhostcatVulnDetectorTest {
  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2020-01-01T00:00:00.00Z"));

  @Inject private GhostcatVulnDetector detector;

  @Rule public MockitoRule rule = MockitoJUnit.rule();
  @Mock public AjpConnection.Factory connectionFactoryMock;
  @Mock public AjpConnection ajpConnectionMock;
  @Mock public AjpResponse ajpResponseMock;

  @Before
  public void setUp() throws IOException {
    Guice.createInjector(
        new FakeUtcClockModule(fakeUtcClock), new GhostcatVulnDetectorBootstrapModule(true),
        new AbstractModule() {
          @Override
          protected void configure() {
            bind(AjpConnection.Factory.class).toProvider(() -> {
              when(connectionFactoryMock.create(any(), anyInt())).thenReturn(ajpConnectionMock);
              return connectionFactoryMock;
            });
          }
        })
        .injectMembers(this);

    when(ajpConnectionMock.performGhostcat(any(), any())).thenReturn(ajpResponseMock);
  }

  @Test
  public void detect_whenAjpConnectorReturns200_returnsVulnerability() {
    when(ajpResponseMock.getStatusCode()).thenReturn(200);
    when(ajpResponseMock.getStatusMessage()).thenReturn("abc");
    when(ajpResponseMock.getHeaders()).thenReturn(ImmutableMultimap.of("x", "y"));
    when(ajpResponseMock.getBodyAsString()).thenReturn("1337");
    NetworkService ajpService = NetworkService.newBuilder().setServiceName("ajp").build();

    DetectionReportList detectionReports =
        detector.detect(TargetInfo.getDefaultInstance(), ImmutableList.of(ajpService));

    assertThat(detectionReports.getDetectionReportsList())
        .containsExactly(
            buildExpectedDetectionReport(
                ajpService, 200, "abc", "{x=[y]}", "1337"));
  }

  @Test
  public void detect_whenAjpConnectorReturns404_returnsVulnerability() {
    when(ajpResponseMock.getStatusCode()).thenReturn(404);
    when(ajpResponseMock.getStatusMessage()).thenReturn("Not found");
    when(ajpResponseMock.getHeaders()).thenReturn(ImmutableMultimap.of("x", "y"));
    when(ajpResponseMock.getBodyAsString()).thenReturn("1337");
    NetworkService ajpService = NetworkService.newBuilder().setServiceName("ajp").build();

    DetectionReportList detectionReports =
        detector.detect(TargetInfo.getDefaultInstance(), ImmutableList.of(ajpService));

    assertThat(detectionReports.getDetectionReportsList())
        .containsExactly(
            buildExpectedDetectionReport(
                ajpService, 404, "Not found", "{x=[y]}", "1337"));
  }

  @Test
  public void detect_whenAjpConnectorReturns500_returnsEmptyDetectionReport() {
    when(ajpResponseMock.getStatusCode()).thenReturn(500);
    when(ajpResponseMock.getStatusMessage()).thenReturn("Internal Server Error");
    when(ajpResponseMock.getHeaders()).thenReturn(ImmutableMultimap.of("x", "y"));
    when(ajpResponseMock.getBodyAsString()).thenReturn("1337");
    NetworkService ajpService = NetworkService.newBuilder().setServiceName("ajp").build();

    DetectionReportList detectionReports =
        detector.detect(TargetInfo.getDefaultInstance(), ImmutableList.of(ajpService));

    assertThat(detectionReports.getDetectionReportsList())
        .containsExactly(
            buildExpectedDetectionReport(
                ajpService, 500, "Internal Server Error", "{x=[y]}", "1337"));
  }

  @Test
  public void detect_whenAjpConnectorReturns403_returnsEmptyDetectionReport() {
    when(ajpResponseMock.getStatusCode()).thenReturn(403);
    when(ajpResponseMock.getStatusMessage()).thenReturn("Forbidden");
    when(ajpResponseMock.getHeaders()).thenReturn(ImmutableMultimap.of("x", "y"));
    when(ajpResponseMock.getBodyAsString()).thenReturn("1337");
    NetworkService ajpService = NetworkService.newBuilder().setServiceName("ajp").build();

    assertThat(
            detector
                .detect(TargetInfo.getDefaultInstance(), ImmutableList.of(ajpService))
                .getDetectionReportsList())
        .isEmpty();
  }

  @Test
  public void detect_whenIOException_returnsEmptyDetectionReport() throws IOException {
    when(ajpConnectionMock.performGhostcat(any(), any())).thenThrow(new IOException());
    NetworkService ajpService = NetworkService.newBuilder().setServiceName("ajp").build();

    assertThat(
            detector
                .detect(TargetInfo.getDefaultInstance(), ImmutableList.of(ajpService))
                .getDetectionReportsList())
        .isEmpty();
  }

  @Test
  public void detect_whenNonAjpMatchedService_returnsEmptyDetectionReport() {
    ImmutableList<NetworkService> nonAjpServices =
        ImmutableList.of(
            NetworkService.newBuilder().setServiceName("ssh").build(),
            NetworkService.newBuilder().setServiceName("rdp").build());

    assertThat(
            detector
                .detect(TargetInfo.getDefaultInstance(), nonAjpServices)
                .getDetectionReportsList())
        .isEmpty();
  }

  private DetectionReport buildExpectedDetectionReport(
      NetworkService ajpService,
      int statusCode,
      String statusMessage,
      String headers,
      String content) {
    return DetectionReport.newBuilder()
        .setTargetInfo(TargetInfo.getDefaultInstance())
        .setNetworkService(ajpService)
        .setDetectionTimestamp(Timestamps.fromMillis(Instant.now(fakeUtcClock).toEpochMilli()))
        .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
        .setVulnerability(
            Vulnerability.newBuilder()
                .setMainId(VulnerabilityId.newBuilder().setPublisher("GOOGLE").setValue("GHOSTCAT"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("Apache Tomcat AJP File Read/Inclusion Vulnerability")
                .setDescription(
                    "Apache Tomcat is an open source web server and servlet container"
                        + " developed by the Apache Software Foundation Apache Tomcat"
                        + " fixed a vulnerability (CVE-2020-1938) that allows an attacker"
                        + " to read any webapps files. If the Tomcat instance supports"
                        + " file uploads, the vulnerability could also be leveraged to"
                        + " achieve remote code execution.")
                .setRecommendation("Install the latest security patches for Apache Tomcat.")
                .addAdditionalDetails(
                    AdditionalDetail.newBuilder()
                        .setTextData(
                            TextData.newBuilder()
                                .setText(
                                    String.format(
                                        "Status code: %d\n"
                                            + "Status message: %s\n"
                                            + "Headers: %s\n"
                                            + "/WEB-INF/web.xml content: %s\n",
                                        statusCode, statusMessage, headers, content)))))
        .build();
  }
}
