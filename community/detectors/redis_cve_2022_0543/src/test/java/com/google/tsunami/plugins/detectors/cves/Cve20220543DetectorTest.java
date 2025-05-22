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
package com.google.tsunami.plugins.detectors.cves;

import static com.google.common.truth.extensions.proto.ProtoTruth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forIpAndPort;
import static com.google.tsunami.plugins.detectors.cves.Cve20220543Detector.DESCRIPTION;
import static com.google.tsunami.plugins.detectors.cves.Cve20220543Detector.RECOMMENDATION;
import static com.google.tsunami.plugins.detectors.cves.Cve20220543Detector.TITLE;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.google.common.collect.ImmutableList;
import com.google.inject.AbstractModule;
import com.google.inject.Guice;
import com.google.inject.multibindings.OptionalBinder;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.common.time.testing.FakeUtcClockModule;
import com.google.tsunami.plugin.payload.testing.FakePayloadGeneratorModule;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.Vulnerability;
import com.google.tsunami.proto.VulnerabilityId;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Arrays;
import javax.inject.Inject;
import javax.net.SocketFactory;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Unit tests for {@link Cve20220543Detector}, showing how to test a detector which utilizes the
 * payload generator framework.
 */
@RunWith(JUnit4.class)
public final class Cve20220543DetectorTest {
  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2020-01-01T00:00:00.00Z"));

  @Inject private Cve20220543Detector detector;

  private final SocketFactory socketFactoryMock = mock(SocketFactory.class);
  private final SecureRandom testSecureRandom =
      new SecureRandom() {
        @Override
        public void nextBytes(byte[] bytes) {
          Arrays.fill(bytes, (byte) 0xFF);
        }
      };

  @Before
  public void setUp() throws IOException {
    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new HttpClientModule.Builder().build(),
            FakePayloadGeneratorModule.builder().setSecureRng(testSecureRandom).build(),
            new Cve20220543DetectorBootstrapModule(),
            new AbstractModule() {
              @Override
              protected void configure() {
                OptionalBinder.newOptionalBinder(binder(), SocketFactory.class)
                    .setBinding()
                    .toInstance(socketFactoryMock);
              }
            })
        .injectMembers(this);
  }

  private void getMock(String output) throws IOException {
    Socket socket = mock(Socket.class);

    when(socketFactoryMock.createSocket()).thenReturn(socket);
    when(socket.getOutputStream()).thenReturn(new ByteArrayOutputStream());
    when(socket.getInputStream()).thenReturn(new ByteArrayInputStream(output.getBytes(UTF_8)));
    when(socket.isConnected()).thenReturn(true);
  }

  @Test
  public void detect_whenVulnerable_reportsVulnerability() throws IOException {
    getMock("TSUNAMI_PAYLOAD_STARTffffffffffffffffTSUNAMI_PAYLOAD_END");
    NetworkService service =
        NetworkService.newBuilder()
            .setNetworkEndpoint(forIpAndPort("127.0.0.1", 6379))
            .setServiceName("redis")
            .build();
    TargetInfo target =
        TargetInfo.newBuilder().addNetworkEndpoints(service.getNetworkEndpoint()).build();

    DetectionReportList detectionReports = detector.detect(target, ImmutableList.of(service));

    assertThat(detectionReports.getDetectionReportsList())
        .containsExactly(
            DetectionReport.newBuilder()
                .setTargetInfo(target)
                .setNetworkService(service)
                .setDetectionTimestamp(
                    Timestamps.fromMillis(Instant.now(fakeUtcClock).toEpochMilli()))
                .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
                .setVulnerability(
                    Vulnerability.newBuilder()
                        .setMainId(
                            VulnerabilityId.newBuilder()
                                .setPublisher("TSUNAMI_COMMUNITY")
                                .setValue("CVE_2022_0543"))
                        .addRelatedId(
                            VulnerabilityId.newBuilder()
                                .setPublisher("CVE")
                                .setValue("CVE-2022-0543"))
                        .setSeverity(Severity.CRITICAL)
                        .setTitle(TITLE)
                        .setDescription(DESCRIPTION)
                        .setRecommendation(RECOMMENDATION))
                .build());
  }

  @Test
  public void detect_whenNotVulnerable_doesNotReportVulnerability() throws IOException {
    getMock("");
    NetworkService service =
        NetworkService.newBuilder()
            .setNetworkEndpoint(forIpAndPort("127.0.0.1", 6379))
            .setServiceName("redis")
            .build();
    TargetInfo target =
        TargetInfo.newBuilder().addNetworkEndpoints(service.getNetworkEndpoint()).build();

    DetectionReportList detectionReports = detector.detect(target, ImmutableList.of(service));

    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
  }
}
