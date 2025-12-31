package com.google.tsunami.plugins.detectors.cves.cve202514847;

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
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.TextData;
import com.google.tsunami.proto.TransportProtocol;
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

@RunWith(JUnit4.class)
public final class Cve202514847DetectorTest {
  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2025-01-01T00:00:00.00Z"));

  private final SocketFactory socketFactoryMock = mock(SocketFactory.class);

  @Inject private Cve202514847Detector detector;

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

  private void configureMockSocket(byte[] responseBytes) throws Exception {
    Socket socket = mock(Socket.class);
    when(socketFactoryMock.createSocket(anyString(), anyInt())).thenReturn(socket);
    when(socket.getOutputStream()).thenReturn(new ByteArrayOutputStream());
    when(socket.getInputStream()).thenReturn(new ByteArrayInputStream(responseBytes));
  }

  @Test
  public void detect_whenVulnerable_returnsVulnerability() throws Exception {
    // A mock MongoDB response that mimics an OP_MSG (opcode 2013)
    // containing the string "field name 'secret_leaked_data'"
    // The detector's extractLeaks method looks for "field name '([^']*)'"
    String leakedContent = "Error: field name 'secret_leaked_data' is invalid";

    // Prefix with some bytes to satisfy msgLen > 25 requirement in detector
    byte[] mockResponse = new byte[100];
    // Set Message Length (first 4 bytes)
    mockResponse[0] = 100;
    // Set OpCode to something other than 2012 (compressed) to trigger raw copy
    mockResponse[12] = (byte) 0xDD;

    System.arraycopy(leakedContent.getBytes(UTF_8), 0, mockResponse, 20, leakedContent.length());

    configureMockSocket(mockResponse);

    NetworkService mongodb =
        NetworkService.newBuilder()
            .setNetworkEndpoint(forIpAndPort("127.0.0.1", 27017))
            .setServiceName("mongodb")
            .setTransportProtocol(TransportProtocol.TCP)
            .build();

    DetectionReportList detectionReports =
        detector.detect(TargetInfo.getDefaultInstance(), ImmutableList.of(mongodb));

    assertThat(detectionReports.getDetectionReportsList())
        .containsExactly(
            DetectionReport.newBuilder()
                .setTargetInfo(TargetInfo.getDefaultInstance())
                .setNetworkService(mongodb)
                .setDetectionTimestamp(
                    Timestamps.fromMillis(Instant.now(fakeUtcClock).toEpochMilli()))
                .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
                .setVulnerability(
                    detector.getAdvisories().get(0).toBuilder()
                        .addAdditionalDetails(
                            AdditionalDetail.newBuilder()
                                .setDescription("Response (first 100 bytes)")
                                .setTextData(TextData.newBuilder().setText("secret_leaked_data"))
                                .build())
                        .build())
                .build());
  }

  @Test
  public void detect_whenNotVulnerable_returnsEmpty() throws Exception {
    // Response that doesn't contain the "field name '...'" pattern
    byte[] safeResponse = new byte[50];
    safeResponse[0] = 50;
    System.arraycopy("Standard MongoDB Response".getBytes(UTF_8), 0, safeResponse, 20, 25);

    configureMockSocket(safeResponse);

    NetworkService mongodb =
        NetworkService.newBuilder()
            .setNetworkEndpoint(forIpAndPort("127.0.0.1", 27017))
            .setServiceName("mongodb")
            .setTransportProtocol(TransportProtocol.TCP)
            .build();

    DetectionReportList detectionReports =
        detector.detect(TargetInfo.getDefaultInstance(), ImmutableList.of(mongodb));

    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
  }

  @Test
  public void detect_whenNotTcp_noVulnerability() throws Exception {
    NetworkService mongodbUdp =
        NetworkService.newBuilder()
            .setNetworkEndpoint(forIpAndPort("127.0.0.1", 27017))
            .setServiceName("mongodb")
            .setTransportProtocol(TransportProtocol.UDP)
            .build();

    DetectionReportList detectionReports =
        detector.detect(TargetInfo.getDefaultInstance(), ImmutableList.of(mongodbUdp));

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

    NetworkService mongodb =
        NetworkService.newBuilder()
            .setNetworkEndpoint(forIpAndPort("127.0.0.1", 27017))
            .setServiceName("mongodb")
            .setTransportProtocol(TransportProtocol.TCP)
            .build();

    DetectionReportList detectionReports =
        detector.detect(TargetInfo.getDefaultInstance(), ImmutableList.of(mongodb));

    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
  }
}
