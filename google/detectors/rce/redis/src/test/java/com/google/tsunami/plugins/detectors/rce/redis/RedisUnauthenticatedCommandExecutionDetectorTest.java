/*
 * Copyright 2021 Google LLC
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
package com.google.tsunami.plugins.detectors.rce.redis;

import static com.google.common.truth.extensions.proto.ProtoTruth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forIpAndPort;
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
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.common.time.testing.FakeUtcClockModule;
import com.google.tsunami.proto.AdditionalDetail;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.TextData;
import com.google.tsunami.proto.TransportProtocol;
import com.google.tsunami.proto.Vulnerability;
import com.google.tsunami.proto.VulnerabilityId;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.time.Instant;
import javax.inject.Inject;
import javax.net.SocketFactory;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

/** Unit tests for {@link RedisUnauthenticatedCommandExecutionDetector}. */
@RunWith(JUnit4.class)
public final class RedisUnauthenticatedCommandExecutionDetectorTest {
  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2020-01-01T00:00:00.00Z"));

  private final SocketFactory socketFactoryMock = mock(SocketFactory.class);

  @Inject private RedisUnauthenticatedCommandExecutionDetector detector;

  @Before
  public void setUp() {
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
            })
        .injectMembers(this);
  }

  private void configureMockSocket(String response) throws Exception {
    Socket socket = mock(Socket.class);
    when(socketFactoryMock.createSocket(anyString(), anyInt())).thenReturn(socket);
    when(socket.getOutputStream()).thenReturn(new ByteArrayOutputStream());
    when(socket.getInputStream()).thenReturn(new ByteArrayInputStream(response.getBytes(UTF_8)));
  }

  @Test
  public void detect_whenAllowsUnauthenticated_returnsVulnerability() throws Exception {
    // first 100 bytes (mock), must contain redis_version field to be positive it is Redis
    final String redisServerInfoResponse = "$100\r\n# Server\r\nredis_version:6.0.15\r\nredis";
    configureMockSocket(redisServerInfoResponse);
    NetworkService redis =
        NetworkService.newBuilder()
            .setNetworkEndpoint(forIpAndPort("127.0.0.1", 6379))
            .setServiceName("redis")
            .setTransportProtocol(TransportProtocol.TCP)
            .build();

    DetectionReportList detectionReports =
        detector.detect(TargetInfo.getDefaultInstance(), ImmutableList.of(redis));

    assertThat(detectionReports.getDetectionReportsList())
        .containsExactly(
            DetectionReport.newBuilder()
                .setTargetInfo(TargetInfo.getDefaultInstance())
                .setNetworkService(redis)
                .setDetectionTimestamp(
                    Timestamps.fromMillis(Instant.now(fakeUtcClock).toEpochMilli()))
                .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
                .setVulnerability(
                    Vulnerability.newBuilder()
                        .setMainId(
                            VulnerabilityId.newBuilder()
                                .setPublisher("GOOGLE")
                                .setValue("REDIS_UNAUTHENTICATED_COMMAND_EXECUTION"))
                        .setSeverity(Severity.CRITICAL)
                        .setTitle("Redis unauthenticated command execution")
                        .setDescription(
                            RedisUnauthenticatedCommandExecutionDetector.VULN_DESCRIPTION)
                        .setRecommendation(
                            RedisUnauthenticatedCommandExecutionDetector.VULN_RECOMMENDATION)
                        .addAdditionalDetails(
                            AdditionalDetail.newBuilder()
                                .setDescription("response (first 100 bytes)")
                                .setTextData(
                                    TextData.newBuilder().setText(redisServerInfoResponse))))
                .build());
  }

  @Test
  public void detect_whenRequiresAuthentication_noVulnerability() throws Exception {
    configureMockSocket("-NOAUTH Authentication required.\r\n");
    NetworkService redis =
        NetworkService.newBuilder()
            .setNetworkEndpoint(forIpAndPort("127.0.0.1", 6379))
            .setServiceName("redis")
            .setTransportProtocol(TransportProtocol.TCP)
            .build();

    DetectionReportList detectionReports =
        detector.detect(TargetInfo.getDefaultInstance(), ImmutableList.of(redis));

    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
  }

  @Test
  public void detect_whenEOF_noVulnerability() throws Exception {
    configureMockSocket("");
    NetworkService redis =
        NetworkService.newBuilder()
            .setNetworkEndpoint(forIpAndPort("127.0.0.1", 6379))
            .setServiceName("redis")
            .setTransportProtocol(TransportProtocol.TCP)
            .build();

    DetectionReportList detectionReports =
        detector.detect(TargetInfo.getDefaultInstance(), ImmutableList.of(redis));

    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
  }

  static class SocketTimeoutExceptionAnswer<T> implements Answer<T> {
    @Override
    public T answer(InvocationOnMock invocation) throws Throwable {
      throw new SocketTimeoutException();
    }
  }

  @Test
  public void detect_whenTimeout_noVulnerability() throws Exception {
    Socket socket = mock(Socket.class);
    when(socketFactoryMock.createSocket(anyString(), anyInt())).thenReturn(socket);
    when(socket.getOutputStream()).thenReturn(new ByteArrayOutputStream());
    InputStream inputStream = mock(InputStream.class, new SocketTimeoutExceptionAnswer<>());
    when(socket.getInputStream()).thenReturn(inputStream);
    NetworkService redis =
        NetworkService.newBuilder()
            .setNetworkEndpoint(forIpAndPort("127.0.0.1", 6379))
            .setServiceName("redis")
            .setTransportProtocol(TransportProtocol.TCP)
            .build();

    DetectionReportList detectionReports =
        detector.detect(TargetInfo.getDefaultInstance(), ImmutableList.of(redis));

    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
  }

  @Test
  public void detect_whenNotRedisResponse_noVulnerability() throws Exception {
    // Redis service response to "info server" command is expected
    // to contain redis_version if command is successful.
    // This test is for the case when it is not a Redis service.
    configureMockSocket("$100\r\n# Server\r\nnon_redis_version:6.0.15\r\n");
    NetworkService notRedis =
        NetworkService.newBuilder()
            .setNetworkEndpoint(forIpAndPort("127.0.0.1", 6379))
            .setServiceName("redis")
            .setTransportProtocol(TransportProtocol.TCP)
            .build();

    DetectionReportList detectionReports =
        detector.detect(TargetInfo.getDefaultInstance(), ImmutableList.of(notRedis));

    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
  }

  @Test
  public void detect_whenNotTcp_noVulnerability() throws Exception {
    configureMockSocket("$100\r\n# Server\r\nredis_version:6.0.15\r\n");
    NetworkService notRedis =
        NetworkService.newBuilder()
            .setNetworkEndpoint(forIpAndPort("127.0.0.1", 6379))
            .setServiceName("redis")
            .setTransportProtocol(TransportProtocol.UDP) // not TCP
            .build();

    DetectionReportList detectionReports =
        detector.detect(TargetInfo.getDefaultInstance(), ImmutableList.of(notRedis));

    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
  }
}
