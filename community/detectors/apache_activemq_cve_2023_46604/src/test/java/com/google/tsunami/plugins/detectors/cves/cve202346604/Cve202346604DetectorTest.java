/*
 * Copyright 2024 Google LLC
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
package com.google.tsunami.plugins.detectors.cves.cve202346604;

import static com.google.common.truth.extensions.proto.ProtoTruth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forIpAndPort;
import static com.google.tsunami.plugins.detectors.cves.cve202346604.Cve202346604Detector.VULN_DESCRIPTION_OF_OOB_VERIFY;
import static com.google.tsunami.plugins.detectors.cves.cve202346604.Cve202346604Detector.VULN_DESCRIPTION_OF_VERSION;
import static com.google.tsunami.plugins.detectors.cves.cve202346604.Cve202346604Detector.SocketFactoryInstance;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.google.common.collect.ImmutableList;
import com.google.inject.AbstractModule;
import com.google.inject.Guice;
import com.google.inject.Key;
import com.google.inject.multibindings.OptionalBinder;
import com.google.inject.testing.fieldbinder.Bind;
import com.google.inject.testing.fieldbinder.BoundFieldModule;
import com.google.inject.util.Modules;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.common.time.testing.FakeUtcClockModule;
import com.google.tsunami.plugin.payload.testing.FakePayloadGeneratorModule;
import com.google.tsunami.plugin.payload.testing.PayloadTestHelper;
import com.google.tsunami.proto.*;

import com.google.tsunami.plugins.detectors.cves.cve202346604.Annotations.OobSleepDuration;

import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Arrays;
import java.util.Map;
import javax.inject.Inject;
import javax.net.SocketFactory;

import okhttp3.mockwebserver.MockWebServer;
import org.apache.activemq.util.MarshallingSupport;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link Cve202346604Detector}. */
@RunWith(JUnit4.class)
public final class Cve202346604DetectorTest {

  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2020-01-01T00:00:00.00Z"));

  private final SocketFactory socketFactoryMock = mock(SocketFactory.class);

  @Inject private Cve202346604Detector detector;

  private final SecureRandom testSecureRandom =
      new SecureRandom() {
        @Override
        public void nextBytes(byte[] bytes) {
          Arrays.fill(bytes, (byte) 0xFF);
        }
      };
  private final MockWebServer mockCallbackServer = new MockWebServer();

  private final TextData details =
      TextData.newBuilder().setText("current version is 5.17.3").build();

  @Bind(lazy = true)
  @OobSleepDuration
  private int sleepDuration = 1;

  @Before
  public void setUp() throws IOException {
    mockCallbackServer.start();
    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            FakePayloadGeneratorModule.builder()
                .setCallbackServer(mockCallbackServer)
                .setSecureRng(testSecureRandom)
                .build(),
            new AbstractModule() {
              @Override
              protected void configure() {
                OptionalBinder.newOptionalBinder(
                        binder(), Key.get(SocketFactory.class, SocketFactoryInstance.class))
                    .setBinding()
                    .toInstance(socketFactoryMock);
              }
            },
            Modules.override(new Cve202346604DetectorBootstrapModule())
                .with(BoundFieldModule.of(this)),
            new HttpClientModule.Builder().build())
        .injectMembers(this);
  }

  public void setUpNoOob() throws IOException {
    mockCallbackServer.shutdown();
    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new Cve202346604DetectorBootstrapModule(),
            FakePayloadGeneratorModule.builder()
                .setCallbackServer(null)
                .setSecureRng(testSecureRandom)
                .build(),
            new AbstractModule() {
              @Override
              protected void configure() {
                OptionalBinder.newOptionalBinder(
                        binder(), Key.get(SocketFactory.class, SocketFactoryInstance.class))
                    .setBinding()
                    .toInstance(socketFactoryMock);
              }
            },
            new HttpClientModule.Builder().build())
        .injectMembers(this);
  }

  @Test
  public void detect_whenVulnerable_returnsVulnerability() throws Exception {
    final byte[] serverInfoResponse =
        new byte[] {
          0, 0, 1, 82, 1, 65, 99, 116, 105, 118, 101, 77, 81, 0, 0, 0, 12, 1, 0, 0, 1, 64, 0, 0, 0,
          13, 0, 17, 83, 116, 97, 99, 107, 84, 114, 97, 99, 101, 69, 110, 97, 98, 108, 101, 100, 1,
          1, 0, 15, 80, 108, 97, 116, 102, 111, 114, 109, 68, 101, 116, 97, 105, 108, 115, 9, 0, 4,
          74, 97, 118, 97, 0, 12, 67, 97, 99, 104, 101, 69, 110, 97, 98, 108, 101, 100, 1, 1, 0, 17,
          84, 99, 112, 78, 111, 68, 101, 108, 97, 121, 69, 110, 97, 98, 108, 101, 100, 1, 1, 0, 18,
          83, 105, 122, 101, 80, 114, 101, 102, 105, 120, 68, 105, 115, 97, 98, 108, 101, 100, 1, 0,
          0, 9, 67, 97, 99, 104, 101, 83, 105, 122, 101, 5, 0, 0, 4, 0, 0, 12, 80, 114, 111, 118,
          105, 100, 101, 114, 78, 97, 109, 101, 9, 0, 8, 65, 99, 116, 105, 118, 101, 77, 81, 0, 20,
          84, 105, 103, 104, 116, 69, 110, 99, 111, 100, 105, 110, 103, 69, 110, 97, 98, 108, 101,
          100, 1, 1, 0, 12, 77, 97, 120, 70, 114, 97, 109, 101, 83, 105, 122, 101, 6, 0, 0, 0, 0, 6,
          64, 0, 0, 0, 21, 77, 97, 120, 73, 110, 97, 99, 116, 105, 118, 105, 116, 121, 68, 117, 114,
          97, 116, 105, 111, 110, 6, 0, 0, 0, 0, 0, 0, 117, 48, 0, 32, 77, 97, 120, 73, 110, 97, 99,
          116, 105, 118, 105, 116, 121, 68, 117, 114, 97, 116, 105, 111, 110, 73, 110, 105, 116, 97,
          108, 68, 101, 108, 97, 121, 6, 0, 0, 0, 0, 0, 0, 39, 16, 0, 19, 77, 97, 120, 70, 114, 97,
          109, 101, 83, 105, 122, 101, 69, 110, 97, 98, 108, 101, 100, 1, 1, 0, 15, 80, 114, 111,
          118, 105, 100, 101, 114, 86, 101, 114, 115, 105, 111, 110, 9, 0, 6, 53, 46, 49, 55, 46, 51
        };

    configureMockSocket(new String(serverInfoResponse, StandardCharsets.UTF_8));
    NetworkService service =
        NetworkService.newBuilder()
            .setNetworkEndpoint(forIpAndPort("127.0.0.1", 1234))
            .setTransportProtocol(TransportProtocol.TCP)
            .setSoftware(Software.newBuilder().setName("ActiveMQ"))
            .build();
    TargetInfo targetInfo = TargetInfo.getDefaultInstance();
    mockCallbackServer.enqueue(PayloadTestHelper.generateMockSuccessfulCallbackResponse());

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
                                .setPublisher("TSUNAMI_COMMUNITY")
                                .setValue("CVE_2023_46604"))
                        .setSeverity(Severity.CRITICAL)
                        .setTitle("CVE-2023-46604 Apache ActiveMQ RCE")
                        .setRecommendation("Upgrade to version 5.15.16, 5.16.7, 5.17.6, or 5.18.3")
                        .setDescription(VULN_DESCRIPTION_OF_OOB_VERIFY)
                        .addAdditionalDetails(AdditionalDetail.newBuilder().setTextData(details)))
                .build());
  }

  @Test
  public void detect_whenNotVulnerable_returnsNoVulnerability() throws Exception {
    final byte[] serverInfoResponse =
        new byte[] {
          0, 0, 1, 82, 1, 65, 99, 116, 105, 118, 101, 77, 81, 0, 0, 0, 12, 1, 0, 0, 1, 64, 0, 0, 0,
          13, 0, 17, 83, 116, 97, 99, 107, 84, 114, 97, 99, 101, 69, 110, 97, 98, 108, 101, 100, 1,
          1, 0, 15, 80, 108, 97, 116, 102, 111, 114, 109, 68, 101, 116, 97, 105, 108, 115, 9, 0, 4,
          74, 97, 118, 97, 0, 12, 67, 97, 99, 104, 101, 69, 110, 97, 98, 108, 101, 100, 1, 1, 0, 17,
          84, 99, 112, 78, 111, 68, 101, 108, 97, 121, 69, 110, 97, 98, 108, 101, 100, 1, 1, 0, 18,
          83, 105, 122, 101, 80, 114, 101, 102, 105, 120, 68, 105, 115, 97, 98, 108, 101, 100, 1, 0,
          0, 9, 67, 97, 99, 104, 101, 83, 105, 122, 101, 5, 0, 0, 4, 0, 0, 12, 80, 114, 111, 118,
          105, 100, 101, 114, 78, 97, 109, 101, 9, 0, 8, 65, 99, 116, 105, 118, 101, 77, 81, 0, 20,
          84, 105, 103, 104, 116, 69, 110, 99, 111, 100, 105, 110, 103, 69, 110, 97, 98, 108, 101,
          100, 1, 1, 0, 12, 77, 97, 120, 70, 114, 97, 109, 101, 83, 105, 122, 101, 6, 0, 0, 0, 0, 6,
          64, 0, 0, 0, 21, 77, 97, 120, 73, 110, 97, 99, 116, 105, 118, 105, 116, 121, 68, 117, 114,
          97, 116, 105, 111, 110, 6, 0, 0, 0, 0, 0, 0, 117, 48, 0, 32, 77, 97, 120, 73, 110, 97, 99,
          116, 105, 118, 105, 116, 121, 68, 117, 114, 97, 116, 105, 111, 110, 73, 110, 105, 116, 97,
          108, 68, 101, 108, 97, 121, 6, 0, 0, 0, 0, 0, 0, 39, 16, 0, 19, 77, 97, 120, 70, 114, 97,
          109, 101, 83, 105, 122, 101, 69, 110, 97, 98, 108, 101, 100, 1, 1, 0, 15, 80, 114, 111,
          118, 105, 100, 101, 114, 86, 101, 114, 115, 105, 111, 110, 9, 0, 6, 53, 46, 49, 55, 46, 54
        };

    configureMockSocket(new String(serverInfoResponse, StandardCharsets.UTF_8));
    NetworkService service =
        NetworkService.newBuilder()
            .setNetworkEndpoint(forIpAndPort("127.0.0.1", 1234))
            .setTransportProtocol(TransportProtocol.TCP)
            .setSoftware(Software.newBuilder().setName("ActiveMQ"))
            .build();
    TargetInfo targetInfo = TargetInfo.getDefaultInstance();
    DetectionReportList detectionReports = detector.detect(targetInfo, ImmutableList.of(service));
    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
  }

  @Test
  public void detect_whenVulnerableWithoutOob_returnsVulnerability() throws Exception {
    this.setUpNoOob();
    final byte[] serverInfoResponse =
        new byte[] {
          0, 0, 1, 82, 1, 65, 99, 116, 105, 118, 101, 77, 81, 0, 0, 0, 12, 1, 0, 0, 1, 64, 0, 0, 0,
          13, 0, 17, 83, 116, 97, 99, 107, 84, 114, 97, 99, 101, 69, 110, 97, 98, 108, 101, 100, 1,
          1, 0, 15, 80, 108, 97, 116, 102, 111, 114, 109, 68, 101, 116, 97, 105, 108, 115, 9, 0, 4,
          74, 97, 118, 97, 0, 12, 67, 97, 99, 104, 101, 69, 110, 97, 98, 108, 101, 100, 1, 1, 0, 17,
          84, 99, 112, 78, 111, 68, 101, 108, 97, 121, 69, 110, 97, 98, 108, 101, 100, 1, 1, 0, 18,
          83, 105, 122, 101, 80, 114, 101, 102, 105, 120, 68, 105, 115, 97, 98, 108, 101, 100, 1, 0,
          0, 9, 67, 97, 99, 104, 101, 83, 105, 122, 101, 5, 0, 0, 4, 0, 0, 12, 80, 114, 111, 118,
          105, 100, 101, 114, 78, 97, 109, 101, 9, 0, 8, 65, 99, 116, 105, 118, 101, 77, 81, 0, 20,
          84, 105, 103, 104, 116, 69, 110, 99, 111, 100, 105, 110, 103, 69, 110, 97, 98, 108, 101,
          100, 1, 1, 0, 12, 77, 97, 120, 70, 114, 97, 109, 101, 83, 105, 122, 101, 6, 0, 0, 0, 0, 6,
          64, 0, 0, 0, 21, 77, 97, 120, 73, 110, 97, 99, 116, 105, 118, 105, 116, 121, 68, 117, 114,
          97, 116, 105, 111, 110, 6, 0, 0, 0, 0, 0, 0, 117, 48, 0, 32, 77, 97, 120, 73, 110, 97, 99,
          116, 105, 118, 105, 116, 121, 68, 117, 114, 97, 116, 105, 111, 110, 73, 110, 105, 116, 97,
          108, 68, 101, 108, 97, 121, 6, 0, 0, 0, 0, 0, 0, 39, 16, 0, 19, 77, 97, 120, 70, 114, 97,
          109, 101, 83, 105, 122, 101, 69, 110, 97, 98, 108, 101, 100, 1, 1, 0, 15, 80, 114, 111,
          118, 105, 100, 101, 114, 86, 101, 114, 115, 105, 111, 110, 9, 0, 6, 53, 46, 49, 55, 46, 51
        };

    configureMockSocket(new String(serverInfoResponse, StandardCharsets.UTF_8));
    NetworkService service =
        NetworkService.newBuilder()
            .setNetworkEndpoint(forIpAndPort("127.0.0.1", 1234))
            .setTransportProtocol(TransportProtocol.TCP)
            .setSoftware(Software.newBuilder().setName("ActiveMQ"))
            .build();
    TargetInfo targetInfo = TargetInfo.getDefaultInstance();
    DetectionReportList detectionReports = detector.detect(targetInfo, ImmutableList.of(service));

    assertThat(detectionReports.getDetectionReportsList())
        .containsExactly(
            DetectionReport.newBuilder()
                .setTargetInfo(targetInfo)
                .setNetworkService(service)
                .setDetectionTimestamp(
                    Timestamps.fromMillis(Instant.now(fakeUtcClock).toEpochMilli()))
                .setDetectionStatus(DetectionStatus.VULNERABILITY_PRESENT)
                .setVulnerability(
                    Vulnerability.newBuilder()
                        .setMainId(
                            VulnerabilityId.newBuilder()
                                .setPublisher("TSUNAMI_COMMUNITY")
                                .setValue("CVE_2023_46604"))
                        .setSeverity(Severity.CRITICAL)
                        .setTitle("CVE-2023-46604 Apache ActiveMQ RCE")
                        .setRecommendation("Upgrade to version 5.15.16, 5.16.7, 5.17.6, or 5.18.3")
                        .setDescription(VULN_DESCRIPTION_OF_VERSION)
                        .addAdditionalDetails(AdditionalDetail.newBuilder().setTextData(details)))
                .build());
  }

  @Test
  public void detect_whenNotVulnerable_returnVersionNotMatch() throws Exception {
    OutputStream os = new ByteArrayOutputStream();
    DataOutputStream dos = new DataOutputStream(os);
    dos.write(new byte[22]);
    MarshallingSupport.marshalPrimitiveMap(Map.of("ProviderVersion", "5.15.17"), dos);
    configureMockSocket(os.toString());
    NetworkService service =
        NetworkService.newBuilder()
            .setNetworkEndpoint(forIpAndPort("127.0.0.1", 1234))
            .setTransportProtocol(TransportProtocol.TCP)
            .setSoftware(Software.newBuilder().setName("ActiveMQ"))
            .build();
    TargetInfo targetInfo = TargetInfo.getDefaultInstance();
    DetectionReportList detectionReports = detector.detect(targetInfo, ImmutableList.of(service));
    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
  }

  private void configureMockSocket(String response) throws Exception {
    Socket socket = mock(Socket.class);
    when(socketFactoryMock.createSocket(anyString(), anyInt())).thenReturn(socket);
    when(socket.getOutputStream()).thenReturn(new ByteArrayOutputStream());
    when(socket.getInputStream()).thenReturn(new ByteArrayInputStream(response.getBytes(UTF_8)));
  }
}
