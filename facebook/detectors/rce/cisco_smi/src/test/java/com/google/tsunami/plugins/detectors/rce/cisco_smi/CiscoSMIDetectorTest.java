/*
 * Copyright 2021 Facebook
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
package com.google.tsunami.plugins.detectors.rce.ciscosmi;

import static com.google.common.truth.extensions.proto.ProtoTruth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostname;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostnameAndPort;
import static org.junit.Assert.assertArrayEquals;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.google.common.collect.ImmutableList;
import com.google.inject.AbstractModule;
import com.google.inject.Guice;
import com.google.inject.multibindings.OptionalBinder;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.common.time.testing.FakeUtcClockModule;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.TransportProtocol;
import com.google.tsunami.proto.Vulnerability;
import com.google.tsunami.proto.VulnerabilityId;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.net.Socket;
import java.time.Instant;
import javax.inject.Inject;
import javax.net.SocketFactory;
import org.junit.Before;
import org.junit.Test;

/** Tests for {@link CiscoSMIDetector}. */
public final class CiscoSMIDetectorTest {

  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2021-01-01T00:00:00.00Z"));

  private final SocketFactory socketFactoryMock = mock(SocketFactory.class);

  @Inject private CiscoSMIDetector detector;

  @Before
  public void setUp() {
    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new AbstractModule() {
              @Override
              protected void configure() {
                OptionalBinder.newOptionalBinder(binder(), SocketFactory.class)
                    .setBinding()
                    .toInstance(socketFactoryMock);
              }
            },
            new CiscoSMIDetectorBootstrapModule())
        .injectMembers(this);
  }

  private ByteArrayOutputStream configureMockSocket(byte[] in) throws Exception {
    Socket socket = mock(Socket.class);
    when(socketFactoryMock.createSocket(anyString(), anyInt())).thenReturn(socket);
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    when(socket.getOutputStream()).thenReturn(out);
    when(socket.getInputStream()).thenReturn(new ByteArrayInputStream(in));
    return out;
  }

  @Test
  public void detect_whenCiscoSMIVulnerable_reportsVuln() throws Exception {
    ByteArrayOutputStream out =
        configureMockSocket(
            new byte[] {
              0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x08,
              0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
            });
    assertThat(
            detector
                .detect(localTargetInfo(), ImmutableList.of(smartInstallService()))
                .getDetectionReportsList())
        .containsExactly(
            DetectionReport.newBuilder()
                .setTargetInfo(localTargetInfo())
                .setNetworkService(smartInstallService())
                .setDetectionTimestamp(Timestamps.fromMillis(fakeUtcClock.millis()))
                .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
                .setVulnerability(
                    Vulnerability.newBuilder()
                        .setMainId(
                            VulnerabilityId.newBuilder()
                                .setPublisher("CISCO")
                                .setValue("CISCO_SA_20170214_SMI"))
                        .setSeverity(Severity.HIGH)
                        .setTitle("Cisco Smart Install Protocol Misuse")
                        .setDescription(
                            "Cisco Smart Install feature should not be exposed as it enables"
                                + " attackers to perform administrative tasks on the device or"
                                + " remotely execute code"))
                .build());
    assertArrayEquals(
        new byte[] {
          0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
          0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x08,
          0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        },
        out.toByteArray());
  }

  @Test
  public void detect_whenCiscoSMINotVulnerable_doesNotReportsVuln() throws Exception {
    configureMockSocket(new byte[] {});
    assertThat(
            detector
                .detect(localTargetInfo(), ImmutableList.of(smartInstallService()))
                .getDetectionReportsList())
        .isEmpty();
  }

  @Test
  public void detect_whenCiscoSMIUnreachable_doesNotReportVuln() throws Exception {
    when(socketFactoryMock.createSocket(anyString(), anyInt()))
        .thenThrow(java.net.SocketException.class);
    assertThat(
            detector
                .detect(localTargetInfo(), ImmutableList.of(smartInstallService()))
                .getDetectionReportsList())
        .isEmpty();
  }

  @Test
  public void detect_whenEmptyNetworkService_generatesEmptyDetectionReports() {
    assertThat(detector.detect(localTargetInfo(), ImmutableList.of()).getDetectionReportsList())
        .isEmpty();
  }

  private static TargetInfo localTargetInfo() {
    return TargetInfo.newBuilder().addNetworkEndpoints(forHostname("localhost")).build();
  }

  private static final NetworkService smartInstallService() {
    return NetworkService.newBuilder()
        .setNetworkEndpoint(forHostnameAndPort("localhost", 4786))
        .setTransportProtocol(TransportProtocol.TCP)
        .setServiceName("smart-install")
        .build();
  }
}
