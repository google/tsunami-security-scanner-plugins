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
package com.google.tsunami.plugins.detectors.rce.cve202226133;

import com.google.common.collect.ImmutableList;
import com.google.inject.AbstractModule;
import com.google.inject.Guice;
import com.google.inject.multibindings.OptionalBinder;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.common.time.testing.FakeUtcClockModule;
import com.google.tsunami.plugin.payload.testing.FakePayloadGeneratorModule;
import com.google.tsunami.plugin.payload.testing.PayloadTestHelper;
import com.google.tsunami.proto.*;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import javax.inject.Inject;
import javax.net.SocketFactory;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.time.Instant;

import static com.google.common.truth.Truth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forIpAndPort;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/** Unit tests for {@link Cve202226133Detector}. */
@RunWith(JUnit4.class)
public final class Cve202226133DetectorTest {
  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2022-10-20T00:00:00.00Z"));
  private final SocketFactory socketFactoryMock = mock(SocketFactory.class);
  private MockWebServer mockCallbackServer;
  @Inject private Cve202226133Detector detector;

  private static TargetInfo targetInfo() {
    return TargetInfo.newBuilder().addNetworkEndpoints(forIpAndPort("127.0.0.1", 5701)).build();
  }

  private static NetworkService bitbucketClusterService() {
    return NetworkService.newBuilder()
        .setNetworkEndpoint(forIpAndPort("127.0.0.1", 5701))
        .setTransportProtocol(TransportProtocol.TCP)
        .setServiceName("unknown")
        .build();
  }

  @Before
  public void setUp() throws IOException {
    mockCallbackServer = new MockWebServer();
    mockCallbackServer.start();

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
            new HttpClientModule.Builder().build(),
            FakePayloadGeneratorModule.builder().setCallbackServer(mockCallbackServer).build(),
            new Cve202226133DetectorBootstrapModule())
        .injectMembers(this);
  }

  @After
  public void tearDown() throws IOException {
    mockCallbackServer.shutdown();
  }

  @Test
  public void detect_whenVulnerable_returnsVulnerability() throws Exception {
    Socket socket = mock(Socket.class);
    when(socketFactoryMock.createSocket(anyString(), anyInt())).thenReturn(socket);
    when(socket.getOutputStream()).thenReturn(new ByteArrayOutputStream());
    when(socket.getInputStream()).thenReturn(new ByteArrayInputStream(
        new byte[] {0, 0, 0, 17, 98, 105, 116, 98, 117, 99, 107, 101, 116, 45, 99, 108, 117, 115, 116, 101, 114}));
    when(socket.getOutputStream()).thenReturn(new ByteArrayOutputStream());

    mockCallbackServer.enqueue(PayloadTestHelper.generateMockSuccessfulCallbackResponse());

    DetectionReportList detectionReports = detector.detect(targetInfo(), ImmutableList.of(bitbucketClusterService()));

    assertThat(detectionReports.getDetectionReportsList())
        .containsExactly(DetectionReport.newBuilder()
            .setTargetInfo(targetInfo())
            .setNetworkService(bitbucketClusterService())
            .setDetectionTimestamp(Timestamps.fromMillis(Instant.now(fakeUtcClock).toEpochMilli()))
            .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
            .setVulnerability(
                Vulnerability.newBuilder()
                    .setMainId(
                        VulnerabilityId.newBuilder()
                            .setPublisher("TSUNAMI_COMMUNITY")
                            .setValue("CVE-2022-26133"))
                    .setSeverity(Severity.CRITICAL)
                    .setTitle("Atlassian Bitbucket DC RCE (CVE-2022-26133)")
                    .setDescription(
                        "SharedSecretClusterAuthenticator in Atlassian Bitbucket Data Center versions"
                            + " 5.14.0 and later before 7.6.14, 7.7.0 and later prior to 7.17.6,"
                            + " 7.18.0 and later prior to 7.18.4, 7.19.0 and later prior"
                            + " to 7.19.4, and 7.20.0 allow a remote, unauthenticated attacker to "
                            + "execute arbitrary code via Java deserialization."))
            .build());
    assertThat(mockCallbackServer.getRequestCount()).isEqualTo(1);
  }

  @Test
  public void detect_whenClusterNameEmpty_noVulnerability() throws Exception {
    Socket socket = mock(Socket.class);
    when(socketFactoryMock.createSocket(anyString(), anyInt())).thenReturn(socket);
    when(socket.getOutputStream()).thenReturn(new ByteArrayOutputStream());
    when(socket.getInputStream()).thenReturn(new ByteArrayInputStream(new byte[]{}));

    assertThat(
        detector
            .detect(targetInfo(), ImmutableList.of(bitbucketClusterService()))
            .getDetectionReportsList())
        .isEmpty();
  }
}
