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
package com.google.tsunami.plugins.detectors.rce.cve202226133;

import static com.google.common.truth.Truth.assertThat;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.google.common.collect.ImmutableList;
import com.google.inject.AbstractModule;
import com.google.inject.Guice;
import com.google.inject.Key;
import com.google.inject.multibindings.OptionalBinder;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.common.time.testing.FakeUtcClockModule;
import com.google.tsunami.plugin.payload.testing.FakePayloadGeneratorModule;
import com.google.tsunami.plugin.payload.testing.PayloadTestHelper;
import com.google.tsunami.plugins.detectors.rce.cve202226133.Cve202226133Detector.SocketFactoryInstance;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.TargetInfo;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.time.Instant;
import javax.inject.Inject;
import javax.net.SocketFactory;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link Cve202226133Detector}. */
@RunWith(JUnit4.class)
public final class Cve202226133DetectorWithCallbackServerTest {
  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2022-10-20T00:00:00.00Z"));
  private final SocketFactory socketFactoryMock = mock(SocketFactory.class);
  private MockWebServer mockCallbackServer;
  @Inject private Cve202226133Detector detector;
  private TargetInfo targetInfo;
  private NetworkService service;

  @Before
  public void setUp() throws IOException {
    mockCallbackServer = new MockWebServer();
    mockCallbackServer.start();

    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new AbstractModule() {
              @Override
              protected void configure() {
                OptionalBinder.newOptionalBinder(
                        binder(), Key.get(SocketFactory.class, SocketFactoryInstance.class))
                    .setBinding()
                    .toInstance(socketFactoryMock);
              }
            },
            new HttpClientModule.Builder().build(),
            FakePayloadGeneratorModule.builder().setCallbackServer(mockCallbackServer).build(),
            new Cve202226133DetectorBootstrapModule())
        .injectMembers(this);

    service = TestHelper.bitbucketClusterService();

    targetInfo = TestHelper.targetInfo();
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
    when(socket.getInputStream()).thenReturn(new ByteArrayInputStream(TestHelper.CLUSTER_NAME));
    when(socket.getOutputStream()).thenReturn(new ByteArrayOutputStream());

    mockCallbackServer.enqueue(PayloadTestHelper.generateMockSuccessfulCallbackResponse());

    DetectionReportList detectionReports = detector.detect(targetInfo, ImmutableList.of(service));

    assertThat(detectionReports.getDetectionReportsList())
        .containsExactly(TestHelper.buildValidDetectionReport(targetInfo, service, fakeUtcClock));
    assertThat(mockCallbackServer.getRequestCount()).isEqualTo(1);
  }

  @Test
  public void detect_whenClusterNameEmpty_noVulnerability() throws Exception {
    Socket socket = mock(Socket.class);
    when(socketFactoryMock.createSocket(anyString(), anyInt())).thenReturn(socket);
    when(socket.getOutputStream()).thenReturn(new ByteArrayOutputStream());
    when(socket.getInputStream()).thenReturn(new ByteArrayInputStream(new byte[] {}));

    assertThat(detector.detect(targetInfo, ImmutableList.of(service)).getDetectionReportsList())
        .isEmpty();
  }
}
