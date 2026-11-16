/*
 * Copyright 2026 Google LLC
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
package com.google.tsunami.plugins.detectors.rce.cve2026119618;

import static com.google.common.truth.Truth.assertThat;
import static com.google.common.truth.extensions.proto.ProtoTruth.assertThat;
import static java.nio.charset.StandardCharsets.ISO_8859_1;
import static java.util.concurrent.TimeUnit.SECONDS;
import static org.junit.Assert.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.google.common.collect.ImmutableList;
import com.google.common.io.BaseEncoding;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.net.socket.TsunamiSocketFactory;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.plugins.detectors.rce.cve2026119618.H2ProbeSession.FrameHeader;
import com.google.tsunami.plugins.detectors.rce.cve2026119618.H2ProbeSession.TransportConnector;
import com.google.tsunami.plugins.detectors.rce.cve2026119618.H2ProbeSession.TransportMode;
import com.google.tsunami.plugins.detectors.rce.cve2026119618.HpackCodec.HeaderField;
import com.google.tsunami.proto.AdditionalDetail;
import com.google.tsunami.proto.CrawlResult;
import com.google.tsunami.proto.CrawlTarget;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.Hostname;
import com.google.tsunami.proto.IpAddress;
import com.google.tsunami.proto.NetworkEndpoint;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.Port;
import com.google.tsunami.proto.ServiceContext;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.TextData;
import com.google.tsunami.proto.TransportProtocol;
import com.google.tsunami.proto.Vulnerability;
import com.google.tsunami.proto.VulnerabilityId;
import com.google.tsunami.proto.WebServiceContext;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;
import javax.net.ssl.ExtendedSSLSession;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link Cve2026119618Detector} and {@link H2ProbeSession}. */
@RunWith(JUnit4.class)
public final class Cve2026119618DetectorTest {

  private static final byte[] clientPreface =
      "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".getBytes(ISO_8859_1);

  private static final Instant FIXED_INSTANT = Instant.parse("2026-11-14T05:00:00.00Z");

  private final FakeUtcClock fakeUtcClock = FakeUtcClock.create().setNow(FIXED_INSTANT);
  private ExecutorService serverExecutor;

  @Before
  public void setUp() {
    serverExecutor = Executors.newCachedThreadPool();
  }

  @After
  public void tearDown() {
    serverExecutor.shutdownNow();
  }

  @Test
  public void detect_whenVulnerableApacheH2cTraceEnableOn_returnsVerifiedCriticalFinding() {
    List<RecordedStream> recorded = Collections.synchronizedList(new ArrayList<>());
    MockApacheConfig cfg = MockApacheConfig.vulnerableTraceEnableOn();
    Cve2026119618Detector detector =
        newDetector((mode, host, port, sniHost, timeout) -> {
          if (mode == TransportMode.H2_TLS) {
            throw new IOException("TLS not enabled");
          }
          return startMockApachePeer(cfg, recorded);
        });

    NetworkService service = buildHttpService("127.0.0.1", 8080, "http");
    TargetInfo targetInfo = buildTargetInfo(service.getNetworkEndpoint());

    DetectionReportList reports = detector.detect(targetInfo, ImmutableList.of(service));

    String expectedDetail =
        "Verified unpatched Apache mod_http2 assign_headers() over HTTP/2 (h2c) at"
            + " http://127.0.0.1:8080/: Stream 1 omitted synthesized 'Content-Length: 0' in"
            + " r->headers_in, Stream 3 confirmed explicit 'Content-Length: 0' preservation, and"
            + " Stream 5 confirmed ap_send_http_trace body handling (HTTP 413 (TraceEnable on)).";
    assertThat(reports)
        .isEqualTo(
            DetectionReportList.newBuilder()
                .addDetectionReports(expectedReport(targetInfo, service, expectedDetail))
                .build());

    assertThat(recorded).hasSize(3);
    assertThat(recorded.get(0).streamId).isEqualTo(1);
    assertThat(recorded.get(0).headers).hasSize(6);
    assertThat(recorded.get(1).streamId).isEqualTo(3);
    assertThat(recorded.get(1).headers).hasSize(7);
    assertThat(recorded.get(2).streamId).isEqualTo(5);
    assertThat(recorded.get(2).headers).hasSize(6);
    assertThat(new String(recorded.get(2).body, ISO_8859_1)).isEqualTo("x");
  }

  @Test
  public void detect_whenVulnerableApacheTlsH2TraceEnableExtended_returnsVerifiedFinding()
      throws Exception {
    SSLContext serverSsl = createSelfSignedServerSslContext();
    List<RecordedStream> recorded = Collections.synchronizedList(new ArrayList<>());
    AtomicReference<List<SNIServerName>> capturedSni = new AtomicReference<>(ImmutableList.of());
    MockApacheConfig cfg = MockApacheConfig.vulnerableTraceEnableExtended();

    TsunamiSocketFactory mockSocketFactory = mock(TsunamiSocketFactory.class);
    when(mockSocketFactory.createSocket(anyString(), anyInt(), any(Duration.class)))
        .thenAnswer(inv -> {
          InMemorySocketPair pair = InMemorySocketPair.create();
          serverExecutor.execute(() -> {
            try (SSLSocket tlsServer =
                wrapServerTls(serverSsl, pair.serverSocket, new String[] {"h2"})) {
              tlsServer.startHandshake();
              if (tlsServer.getSession() instanceof ExtendedSSLSession ext) {
                capturedSni.set(ext.getRequestedServerNames());
              }
              serveMockApacheH2(tlsServer, cfg, recorded);
            } catch (IOException ignored) {
              // Expected on teardown.
            }
          });
          return pair.clientSocket;
        });

    Cve2026119618Detector detector =
        new Cve2026119618Detector(
            fakeUtcClock,
            H2ProbeSession.defaultConnector(mockSocketFactory),
            Duration.ofSeconds(3),
            sequentialNonceSupplier());

    NetworkService service =
        NetworkService.newBuilder()
            .setTransportProtocol(TransportProtocol.TCP)
            .setServiceName("https")
            .setNetworkEndpoint(
                NetworkEndpoint.newBuilder()
                    .setHostname(Hostname.newBuilder().setName("apache.example.test"))
                    .setIpAddress(IpAddress.newBuilder().setAddress("127.0.0.1"))
                    .setPort(Port.newBuilder().setPortNumber(8443)))
            .build();
    TargetInfo targetInfo = buildTargetInfo(service.getNetworkEndpoint());

    DetectionReportList reports = detector.detect(targetInfo, ImmutableList.of(service));

    String expectedDetail =
        "Verified unpatched Apache mod_http2 assign_headers() over HTTP/2 (h2) at"
            + " https://apache.example.test:8443/: Stream 1 omitted synthesized"
            + " 'Content-Length: 0' in r->headers_in, Stream 3 confirmed explicit"
            + " 'Content-Length: 0' preservation, and Stream 5 confirmed ap_send_http_trace body"
            + " handling (HTTP 200 echoed 1-byte body (TraceEnable extended)).";
    assertThat(reports)
        .isEqualTo(
            DetectionReportList.newBuilder()
                .addDetectionReports(expectedReport(targetInfo, service, expectedDetail))
                .build());
    assertThat(capturedSni.get()).containsExactly(new SNIHostName("apache.example.test"));
  }

  @Test
  public void detect_negativeConfounderMatrix_emitsZeroFalsePositives() {
    ImmutableList<MockApacheConfig> confounders =
        ImmutableList.of(
            // (a) Patched >= 2.4.71 / <= 2.4.54 echoing Title-Case Content-Length: 0 on Stream 1
            MockApacheConfig.vulnerableTraceEnableOn().withStream1ContentLength("Content-Length"),
            // (a) Distro backport / lowercase content-length: 0 on Stream 1 (kills MT-1 #2)
            MockApacheConfig.vulnerableTraceEnableOn().withStream1ContentLength("content-length"),
            // (b) mod_headers RequestHeader unset Content-Length on Stream 1 & Stream 3 (kills MT-1
            // #3)
            MockApacheConfig.vulnerableTraceEnableOn().withOmitStream3ContentLength(),
            // (c) HTTP/2-to-HTTP/1.1 reverse proxy echoing HTTP/1.1 request line
            MockApacheConfig.vulnerableTraceEnableOn().withHttp11EchoLine(),
            // (d) Non-Apache Tomcat/Jetty echoing lowercase x-tsunami-probe (kills MT-1 #1)
            MockApacheConfig.vulnerableTraceEnableOn().withLowercaseProbeEcho(),
            // (d) Non-Apache echoing lowercase host header (kills MT-1 #1)
            MockApacheConfig.vulnerableTraceEnableOn().withLowercaseHostEcho(),
            // (e) Title-Case echoer returning 200 on Stream 5 without 'x' body (kills MT-1 #4)
            MockApacheConfig.vulnerableTraceEnableExtended().withOmitStream5Body(),
            // Stream 5 200 without Content-Length: 1
            MockApacheConfig.vulnerableTraceEnableExtended().withOmitStream5ContentLength(),
            // Stream 5 returning 500 (TraceEnable on)
            MockApacheConfig.vulnerableTraceEnableOn().withStream5Status("500"),
            // Stream 5 returning 500 with valid message/http TraceEnable extended echo body
            MockApacheConfig.vulnerableTraceEnableExtended().withStream5Status("500"),
            // Stream 5 returning 200 with non-message/http Content-Type and valid echo body
            MockApacheConfig.vulnerableTraceEnableExtended().withStream5ContentType("text/plain"),
            // Wrong response Content-Type on Stream 1
            MockApacheConfig.vulnerableTraceEnableOn().withResponseContentType("text/html"),
            // Malformed (unterminated) TRACE body on Stream 1
            MockApacheConfig.vulnerableTraceEnableOn().withMalformedStream1Body(),
            // Stream 3 returning non-200 status
            MockApacheConfig.vulnerableTraceEnableOn().withStream3Status("400"),
            // Stream 3 echoing Content-Length: 0 but mismatched X-Tsunami-Probe nonce
            MockApacheConfig.vulnerableTraceEnableOn().withStream3BadNonce(),
            // Malformed (unterminated) TRACE body on Stream 3
            MockApacheConfig.vulnerableTraceEnableOn().withMalformedStream3Body(),
            // Malformed (unterminated) TRACE body on Stream 5
            MockApacheConfig.vulnerableTraceEnableExtended().withMalformedStream5Body());

    NetworkService service = buildHttpService("127.0.0.1", 8080, "http");
    TargetInfo targetInfo = buildTargetInfo(service.getNetworkEndpoint());

    for (MockApacheConfig confounder : confounders) {
      List<RecordedStream> recorded = Collections.synchronizedList(new ArrayList<>());
      Cve2026119618Detector detector =
          newDetector((mode, host, port, sniHost, timeout) -> {
            if (mode == TransportMode.H2_TLS) {
              throw new IOException("h2c only");
            }
            return startMockApachePeer(confounder, recorded);
          });

      DetectionReportList reports = detector.detect(targetInfo, ImmutableList.of(service));
      assertThat(reports.getDetectionReportsList()).isEmpty();
    }
  }

  @Test
  public void detect_whenTraceEnableOffReturns405OnRoot_shortCircuitsWithoutProbingCrawledPaths() {
    List<RecordedStream> recorded = Collections.synchronizedList(new ArrayList<>());
    MockApacheConfig cfg = MockApacheConfig.vulnerableTraceEnableOn().withStream1Status("405");

    Cve2026119618Detector detector =
        newDetector((mode, host, port, sniHost, timeout) -> {
          if (mode == TransportMode.H2_TLS) {
            throw new IOException("h2c only");
          }
          return startMockApachePeer(cfg, recorded);
        });

    NetworkService service =
        buildHttpService("127.0.0.1", 8080, "http").toBuilder()
            .setServiceContext(
                ServiceContext.newBuilder()
                    .setWebServiceContext(
                        WebServiceContext.newBuilder()
                            .addCrawlResults(
                                CrawlResult.newBuilder()
                                    .setCrawlTarget(
                                        CrawlTarget.newBuilder()
                                            .setUrl("http://127.0.0.1:8080/fallback1")))
                            .addCrawlResults(
                                CrawlResult.newBuilder()
                                    .setCrawlTarget(
                                        CrawlTarget.newBuilder()
                                            .setUrl("http://127.0.0.1:8080/fallback2")))))
            .build();

    DetectionReportList reports =
        detector.detect(buildTargetInfo(service.getNetworkEndpoint()), ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(recorded).hasSize(1);
    assertThat(recorded.get(0).headerMap()).containsEntry(":path", "/");

    // Verify Stream 1 non-message/http Content-Type stops immediately after Stream 1 without
    // sending Stream 3 or probing fallback crawled paths.
    List<RecordedStream> htmlRecorded = Collections.synchronizedList(new ArrayList<>());
    MockApacheConfig htmlCfg =
        MockApacheConfig.vulnerableTraceEnableOn().withResponseContentType("text/html");
    Cve2026119618Detector htmlDetector =
        newDetector((mode, host, port, sniHost, timeout) -> {
          if (mode == TransportMode.H2_TLS) {
            throw new IOException("h2c only");
          }
          return startMockApachePeer(htmlCfg, htmlRecorded);
        });
    assertThat(
            htmlDetector
                .detect(buildTargetInfo(service.getNetworkEndpoint()), ImmutableList.of(service))
                .getDetectionReportsList())
        .isEmpty();
    assertThat(htmlRecorded).hasSize(1);

    // Verify default port selection when NetworkEndpoint omits an explicit port (443 for https, 80
    // for http).
    List<Integer> observedPorts = Collections.synchronizedList(new ArrayList<>());
    Cve2026119618Detector portCheckDetector =
        newDetector((mode, host, port, sniHost, timeout) -> {
          observedPorts.add(port);
          throw new IOException("abort after recording port");
        });
    NetworkService portlessHttps =
        NetworkService.newBuilder()
            .setTransportProtocol(TransportProtocol.TCP)
            .setServiceName("https")
            .setNetworkEndpoint(
                NetworkEndpoint.newBuilder()
                    .setIpAddress(IpAddress.newBuilder().setAddress("127.0.0.1")))
            .build();
    NetworkService portlessHttp =
        NetworkService.newBuilder()
            .setTransportProtocol(TransportProtocol.TCP)
            .setServiceName("http")
            .setNetworkEndpoint(
                NetworkEndpoint.newBuilder()
                    .setIpAddress(IpAddress.newBuilder().setAddress("127.0.0.1")))
            .build();
    assertThat(
            portCheckDetector
                .detect(
                    buildTargetInfo(portlessHttps.getNetworkEndpoint()),
                    ImmutableList.of(portlessHttps, portlessHttp))
                .getDetectionReportsList())
        .isEmpty();
    assertThat(observedPorts).containsExactly(443, 443, 80, 80).inOrder();
    assertThat(Cve2026119618Detector.randomHexNonce()).isNotEqualTo("0000000000000000");
  }

  @Test
  public void detect_withPaddedPriorityReservedMsbSplitHuffmanContinuationAndPing_succeeds() {
    AtomicBoolean sawPingAck = new AtomicBoolean(false);
    byte[] pingData = "pingdata".getBytes(ISO_8859_1);
    // Exact RFC 7541 Huffman encoding of "message/http": a4 a8 40 e6 2b 13 a5 35 ff
    byte[] huffmanMessageHttp = BaseEncoding.base16().lowerCase().decode("a4a840e62b13a535ff");

    Cve2026119618Detector detector =
        newDetector((mode, host, port, sniHost, timeout) -> {
          if (mode == TransportMode.H2_TLS) {
            throw new IOException("h2c only");
          }
          InMemorySocketPair pair = InMemorySocketPair.create();
          serverExecutor.execute(() -> {
            try (Socket srv = pair.serverSocket) {
              InputStream in = srv.getInputStream();
              OutputStream out = srv.getOutputStream();
              in.readNBytes(clientPreface.length);
              writeFrame(out, H2ProbeSession.FRAME_SETTINGS, 0, 0, new byte[0]);

              HpackCodec.Decoder reqDec = new HpackCodec.Decoder(4096);
              for (int step = 1; step <= 3; step++) {
                RecordedStream req = readNextRequestStream(in, out, reqDec, pingData, sawPingAck);
                int streamIdWithMsb = req.streamId | 0x80000000;

                // Interleave PING (requiring PING ACK) and WINDOW_UPDATE.
                writeFrame(out, H2ProbeSession.FRAME_PING, 0, 0, pingData);
                writeFrame(out, H2ProbeSession.FRAME_WINDOW_UPDATE, 0, 0, new byte[] {0, 0, 4, 0});

                if (step == 3) {
                  byte[] h413 =
                      HpackCodec.encodeLiteralNeverIndexed(
                          ImmutableList.of(new HeaderField(":status", "413")));
                  ByteArrayOutputStream padded = new ByteArrayOutputStream();
                  padded.write(2); // pad len
                  padded.writeBytes(new byte[] {(byte) 0x80, 0, 0, 0, 15}); // priority
                  padded.writeBytes(h413);
                  padded.writeBytes(new byte[] {0, 0});
                  int flags =
                      H2ProbeSession.FLAG_PADDED
                          | H2ProbeSession.FLAG_PRIORITY
                          | H2ProbeSession.FLAG_END_HEADERS
                          | H2ProbeSession.FLAG_END_STREAM;
                  writeFrame(
                      out,
                      H2ProbeSession.FRAME_HEADERS,
                      flags,
                      streamIdWithMsb,
                      padded.toByteArray());
                  // Drain final PING ACK before closing socket.
                  readNextRequestStreamOrAck(in, pingData, sawPingAck);
                  return;
                }

                // Build HPACK block with :status=200 (0x88) + incremental-indexed
                // content-type (0x5f) + Huffman string split across HEADERS + 2 CONTINUATIONs!
                ByteArrayOutputStream fullBlock = new ByteArrayOutputStream();
                fullBlock.write(0x88);
                fullBlock.write(0x5f);
                fullBlock.write(0x80 | huffmanMessageHttp.length);
                fullBlock.writeBytes(huffmanMessageHttp);
                byte[] raw = fullBlock.toByteArray();

                ByteArrayOutputStream firstFrag = new ByteArrayOutputStream();
                firstFrag.write(3); // pad length
                firstFrag.writeBytes(new byte[] {0, 0, 0, 0, 32}); // priority
                firstFrag.write(raw, 0, 5); // split right inside Huffman bytes!
                firstFrag.writeBytes(new byte[] {0, 0, 0});
                writeFrame(
                    out,
                    H2ProbeSession.FRAME_HEADERS,
                    H2ProbeSession.FLAG_PADDED | H2ProbeSession.FLAG_PRIORITY,
                    streamIdWithMsb,
                    firstFrag.toByteArray());
                writeFrame(
                    out,
                    H2ProbeSession.FRAME_CONTINUATION,
                    0,
                    streamIdWithMsb,
                    Arrays.copyOfRange(raw, 5, 9));
                writeFrame(
                    out,
                    H2ProbeSession.FRAME_CONTINUATION,
                    H2ProbeSession.FLAG_END_HEADERS,
                    streamIdWithMsb,
                    Arrays.copyOfRange(raw, 9, raw.length));

                Map<String, String> hm = req.headerMap();
                String echo =
                    "TRACE "
                        + hm.get(":path")
                        + " HTTP/2.0\r\nHost: "
                        + hm.get(":authority")
                        + "\r\nContent-Type: text/plain\r\n"
                        + (step == 2 ? "Content-Length: 0\r\n" : "")
                        + "X-Tsunami-Probe: "
                        + hm.get("x-tsunami-probe")
                        + "\r\n\r\n";
                byte[] echoBytes = echo.getBytes(ISO_8859_1);
                ByteArrayOutputStream paddedData = new ByteArrayOutputStream();
                paddedData.write(2);
                paddedData.writeBytes(echoBytes);
                paddedData.writeBytes(new byte[] {0, 0});
                writeFrame(
                    out,
                    H2ProbeSession.FRAME_DATA,
                    H2ProbeSession.FLAG_PADDED | H2ProbeSession.FLAG_END_STREAM,
                    streamIdWithMsb,
                    paddedData.toByteArray());
              }
            } catch (IOException ignored) {
              // Expected on completion.
            }
          });
          return pair.clientSocket;
        });

    NetworkService service = buildHttpService("127.0.0.1", 8080, "http");
    DetectionReportList reports =
        detector.detect(buildTargetInfo(service.getNetworkEndpoint()), ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList()).hasSize(1);
    assertThat(sawPingAck.get()).isTrue();
  }

  @Test
  public void detect_whenServerSendsGoAwayAfterStream1OrStream3_reconnectsWithStream1AndFreshHpack()
      throws Exception {
    for (int goAwayAfterStreamsOnConn1 : new int[] {1, 2}) {
      AtomicInteger connCounter = new AtomicInteger(0);
      AtomicInteger reconnectFirstStreamId = new AtomicInteger(0);

      Cve2026119618Detector detector =
          newDetector((mode, host, port, sniHost, timeout) -> {
            if (mode == TransportMode.H2_TLS) {
              throw new IOException("h2c only");
            }
            int connNum = connCounter.incrementAndGet();
            InMemorySocketPair pair = InMemorySocketPair.create();
            serverExecutor.execute(() -> {
              try (Socket srv = pair.serverSocket) {
                InputStream in = srv.getInputStream();
                OutputStream out = srv.getOutputStream();
                in.readNBytes(clientPreface.length);
                writeFrame(out, H2ProbeSession.FRAME_SETTINGS, 0, 0, new byte[0]);
                HpackCodec.Decoder reqDec = new HpackCodec.Decoder(4096);
                int streamsOnConn = 0;
                AtomicBoolean indexedCt = new AtomicBoolean(false);
                while (true) {
                  RecordedStream req =
                      readNextRequestStream(in, out, reqDec, new byte[8], new AtomicBoolean());
                  streamsOnConn++;
                  if (connNum == 2 && streamsOnConn == 1) {
                    reconnectFirstStreamId.set(req.streamId);
                  }
                  if (connNum == 1 && streamsOnConn == goAwayAfterStreamsOnConn1) {
                    byte[] goAwayPayload = new byte[] {0, 0, 0, (byte) req.streamId, 0, 0, 0, 0};
                    // On goAwayAfterStreamsOnConn1 == 1, send GOAWAY before the response so
                    // peerGoAway is observed on the active stream and triggers pre-roundTrip
                    // reconnect on the next stream; on 2, send GOAWAY after response.
                    if (goAwayAfterStreamsOnConn1 == 1) {
                      writeFrame(out, H2ProbeSession.FRAME_GOAWAY, 0, 0, goAwayPayload);
                      writeMockApacheResponse(
                          out, req, indexedCt, MockApacheConfig.vulnerableTraceEnableOn());
                    } else {
                      writeMockApacheResponse(
                          out, req, indexedCt, MockApacheConfig.vulnerableTraceEnableOn());
                      writeFrame(out, H2ProbeSession.FRAME_GOAWAY, 0, 0, goAwayPayload);
                    }
                    return;
                  }
                  writeMockApacheResponse(
                      out, req, indexedCt, MockApacheConfig.vulnerableTraceEnableOn());
                }
              } catch (IOException ignored) {
                // Expected on teardown.
              }
            });
            return pair.clientSocket;
          });

      NetworkService service = buildHttpService("127.0.0.1", 8080, "http");
      DetectionReportList reports =
          detector.detect(buildTargetInfo(service.getNetworkEndpoint()), ImmutableList.of(service));

      assertThat(reports.getDetectionReportsList()).hasSize(1);
      assertThat(connCounter.get()).isEqualTo(2);
      assertThat(reconnectFirstStreamId.get()).isEqualTo(1);
    }

    // Also verify real OS loopback TCP RST (SocketException) reconnection after Stream 1 GOAWAY +
    // close.
    InetAddress loopback = InetAddress.getLoopbackAddress();
    try (ServerSocket serverSocket = new ServerSocket(0, 50, loopback)) {
      AtomicInteger tcpConns = new AtomicInteger(0);
      List<RecordedStream> recorded = Collections.synchronizedList(new ArrayList<>());
      Future<?> acceptLoop =
          serverExecutor.submit(() -> {
            while (!serverSocket.isClosed()) {
              Socket srv;
              try {
                srv = serverSocket.accept();
              } catch (IOException e) {
                return;
              }
              int cNum = tcpConns.incrementAndGet();
              serverExecutor.execute(() -> {
                try (srv) {
                  InputStream in = srv.getInputStream();
                  OutputStream out = srv.getOutputStream();
                  in.readNBytes(clientPreface.length);
                  writeFrame(out, H2ProbeSession.FRAME_SETTINGS, 0, 0, new byte[0]);
                  HpackCodec.Decoder reqDec = new HpackCodec.Decoder(4096);
                  AtomicBoolean indexedCt = new AtomicBoolean(false);
                  if (cNum == 1) {
                    RecordedStream req =
                        readNextRequestStream(in, out, reqDec, new byte[8], new AtomicBoolean());
                    writeMockApacheResponse(
                        out, req, indexedCt, MockApacheConfig.vulnerableTraceEnableOn());
                    byte[] goaway = new byte[] {0, 0, 0, 1, 0, 0, 0, 0};
                    writeFrame(out, H2ProbeSession.FRAME_GOAWAY, 0, 0, goaway);
                    return;
                  }
                  while (true) {
                    RecordedStream req =
                        readNextRequestStream(in, out, reqDec, new byte[8], new AtomicBoolean());
                    recorded.add(req);
                    writeMockApacheResponse(
                        out, req, indexedCt, MockApacheConfig.vulnerableTraceEnableOn());
                  }
                } catch (IOException ignored) {
                  // Expected on disconnect.
                }
              });
            }
          });

      int tcpPort = serverSocket.getLocalPort();
      Cve2026119618Detector tcpDetector =
          newDetector((mode, host, port, sniHost, timeout) -> {
            if (mode == TransportMode.H2_TLS) {
              throw new IOException("h2c only");
            }
            Socket client = new Socket(loopback, tcpPort);
            client.setSoTimeout(2000);
            return client;
          });
      NetworkService tcpSvc = buildHttpService(loopback.getHostAddress(), tcpPort, "http");
      DetectionReportList tcpReports =
          tcpDetector.detect(
              buildTargetInfo(tcpSvc.getNetworkEndpoint()), ImmutableList.of(tcpSvc));
      assertThat(tcpReports.getDetectionReportsList()).hasSize(1);
      assertThat(tcpConns.get()).isEqualTo(2);
      serverSocket.close();
      acceptLoop.get(2, SECONDS);
    }
  }

  @Test
  public void detect_whenHttp11OrOversizedOrExcessiveContinuations_rejectsFastWithoutStall() {
    ImmutableList<PeerScript> adversarialPeers =
        ImmutableList.of(
            // (d) HTTP/1.1 400 Bad Request ("HTT" = 4.74 MiB frame length; kills MT-2 #4!)
            (in, out) -> {
              in.readNBytes(clientPreface.length);
              out.write(
                  "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n".getBytes(ISO_8859_1));
              out.flush();
              while (in.read() != -1) {
                // Hold pipe open until client rejects at 9-byte header gate and closes socket.
              }
            },
            // (d2) Non-SETTINGS first frame followed by vulnerable responses (deterministic gate
            // check)
            (in, out) -> {
              in.readNBytes(clientPreface.length);
              writeFrame(out, H2ProbeSession.FRAME_PING, H2ProbeSession.FLAG_ACK, 0, new byte[8]);
              HpackCodec.Decoder reqDec = new HpackCodec.Decoder(4096);
              AtomicBoolean indexedCt = new AtomicBoolean(false);
              while (true) {
                RecordedStream req =
                    readNextRequestStream(in, out, reqDec, new byte[8], new AtomicBoolean());
                writeMockApacheResponse(
                    out, req, indexedCt, MockApacheConfig.vulnerableTraceEnableOn());
              }
            },
            // (e) Oversized frame length (> 16384)
            (in, out) -> {
              in.readNBytes(clientPreface.length);
              out.write(new byte[] {0x00, 0x50, 0x00, 0x04, 0x00, 0, 0, 0, 0}); // 20480 > 16384
              out.flush();
            },
            // (e) Excessive CONTINUATION frames (> 16)
            (in, out) -> {
              in.readNBytes(clientPreface.length);
              writeFrame(out, H2ProbeSession.FRAME_SETTINGS, 0, 0, new byte[0]);
              HpackCodec.Decoder dec = new HpackCodec.Decoder(4096);
              RecordedStream req =
                  readNextRequestStream(in, out, dec, new byte[8], new AtomicBoolean());
              writeFrame(
                  out, H2ProbeSession.FRAME_HEADERS, 0, req.streamId, new byte[] {(byte) 0x88});
              for (int i = 0; i < 20; i++) {
                writeFrame(out, H2ProbeSession.FRAME_CONTINUATION, 0, req.streamId, new byte[0]);
              }
            });

    NetworkService service = buildHttpService("127.0.0.1", 8080, "http");
    TargetInfo targetInfo = buildTargetInfo(service.getNetworkEndpoint());

    for (PeerScript script : adversarialPeers) {
      long startNanos = System.nanoTime();
      Cve2026119618Detector detector =
          new Cve2026119618Detector(
              fakeUtcClock,
              (mode, host, port, sniHost, timeout) -> {
                if (mode == TransportMode.H2_TLS) {
                  throw new IOException("h2c only");
                }
                InMemorySocketPair pair = InMemorySocketPair.create();
                serverExecutor.execute(() -> {
                  try (Socket srv = pair.serverSocket) {
                    script.run(srv.getInputStream(), srv.getOutputStream());
                  } catch (IOException | InterruptedException ignored) {
                    // Expected when client aborts early.
                  }
                });
                return pair.clientSocket;
              },
              Duration.ofMillis(1200),
              sequentialNonceSupplier());

      DetectionReportList reports = detector.detect(targetInfo, ImmutableList.of(service));
      long elapsedMs = Duration.ofNanos(System.nanoTime() - startNanos).toMillis();

      assertThat(reports.getDetectionReportsList()).isEmpty();
      assertThat(elapsedMs).isLessThan(1000L);
    }
  }

  @Test
  public void defaultConnector_rejectsNonH2AlpnAndSuppressesSniWhenSniHostEmpty() throws Exception {
    SSLContext serverSsl = createSelfSignedServerSslContext();
    AtomicInteger appBytesReadOnNonH2 = new AtomicInteger(0);
    List<RecordedStream> recorded = Collections.synchronizedList(new ArrayList<>());

    // 1. Server negotiates empty ALPN (ignores ALPN extension) AND would serve vulnerable HTTP/2 if
    // client fails to verify ALPN == "h2" (kills MT-1 #5!).
    TsunamiSocketFactory nonH2Factory = mock(TsunamiSocketFactory.class);
    when(nonH2Factory.createSocket(anyString(), anyInt(), any(Duration.class)))
        .thenAnswer(inv -> {
          InMemorySocketPair pair = InMemorySocketPair.create();
          serverExecutor.execute(() -> {
            try (SSLSocket tlsServer = wrapServerTls(serverSsl, pair.serverSocket, new String[0])) {
              tlsServer.startHandshake();
              int firstByte = tlsServer.getInputStream().read();
              if (firstByte >= 0) {
                appBytesReadOnNonH2.incrementAndGet();
                serveMockApacheH2WithFirstByte(
                    tlsServer,
                    (byte) firstByte,
                    MockApacheConfig.vulnerableTraceEnableOn(),
                    recorded);
              }
            } catch (IOException ignored) {
              // Expected when client closes immediately after ALPN check.
            }
          });
          return pair.clientSocket;
        });

    Cve2026119618Detector detector =
        new Cve2026119618Detector(
            fakeUtcClock,
            H2ProbeSession.defaultConnector(nonH2Factory),
            Duration.ofSeconds(2),
            sequentialNonceSupplier());
    NetworkService httpsSvc = buildHttpService("127.0.0.1", 8443, "https");
    DetectionReportList reports =
        detector.detect(buildTargetInfo(httpsSvc.getNetworkEndpoint()), ImmutableList.of(httpsSvc));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(appBytesReadOnNonH2.get()).isEqualTo(0);

    // 2. Verify explicit SNI suppression when sniHost is empty even if host string is non-IP.
    CountDownLatch sniCaptured = new CountDownLatch(1);
    AtomicReference<List<SNIServerName>> serverObservedSni =
        new AtomicReference<>(ImmutableList.of(new SNIHostName("unexpected.example.test")));
    TsunamiSocketFactory sniCheckFactory = mock(TsunamiSocketFactory.class);
    when(sniCheckFactory.createSocket(anyString(), anyInt(), any(Duration.class)))
        .thenAnswer(inv -> {
          InMemorySocketPair pair = InMemorySocketPair.create();
          serverExecutor.execute(() -> {
            try (SSLSocket tlsServer =
                wrapServerTls(serverSsl, pair.serverSocket, new String[] {"h2"})) {
              tlsServer.startHandshake();
              if (tlsServer.getSession() instanceof ExtendedSSLSession ext) {
                serverObservedSni.set(ext.getRequestedServerNames());
              }
            } catch (IOException ignored) {
              // Handshake complete.
            } finally {
              sniCaptured.countDown();
            }
          });
          return pair.clientSocket;
        });

    TransportConnector connector = H2ProbeSession.defaultConnector(sniCheckFactory);
    try (Socket clientTls =
        connector.connect(
            TransportMode.H2_TLS, "internal-alias.example.test", 8443, "", Duration.ofSeconds(2))) {
      assertThat(clientTls).isInstanceOf(SSLSocket.class);
      assertThat(sniCaptured.await(2, SECONDS)).isTrue();
    }
    assertThat(serverObservedSni.get()).isEmpty();

    // 3. Verify non-STD3 underscored sniHost falls back cleanly without IllegalArgumentException.
    CountDownLatch underscoreCaptured = new CountDownLatch(1);
    AtomicReference<List<SNIServerName>> underscoreObservedSni =
        new AtomicReference<>(ImmutableList.of(new SNIHostName("unexpected.example.test")));
    TsunamiSocketFactory underscoreFactory = mock(TsunamiSocketFactory.class);
    when(underscoreFactory.createSocket(anyString(), anyInt(), any(Duration.class)))
        .thenAnswer(inv -> {
          InMemorySocketPair pair = InMemorySocketPair.create();
          serverExecutor.execute(() -> {
            try (SSLSocket tlsServer =
                wrapServerTls(serverSsl, pair.serverSocket, new String[] {"h2"})) {
              tlsServer.startHandshake();
              if (tlsServer.getSession() instanceof ExtendedSSLSession ext) {
                underscoreObservedSni.set(ext.getRequestedServerNames());
              }
            } catch (IOException ignored) {
              // Handshake complete.
            } finally {
              underscoreCaptured.countDown();
            }
          });
          return pair.clientSocket;
        });

    TransportConnector underscoreConnector = H2ProbeSession.defaultConnector(underscoreFactory);
    try (Socket clientTls =
        underscoreConnector.connect(
            TransportMode.H2_TLS,
            "127.0.0.1",
            8443,
            "apache_internal.example.test",
            Duration.ofSeconds(2))) {
      assertThat(clientTls).isInstanceOf(SSLSocket.class);
      assertThat(underscoreCaptured.await(2, SECONDS)).isTrue();
    }
    assertThat(underscoreObservedSni.get()).isEmpty();
  }

  @Test
  public void serviceEligibilityTransportOrderIpv6AndCrawledFallback_matchGoParity()
      throws IOException {
    assertThat(
            Cve2026119618Detector.isSupportedService(
                NetworkService.newBuilder()
                    .setTransportProtocol(TransportProtocol.UDP)
                    .setServiceName("http")
                    .build()))
        .isFalse();
    assertThat(
            Cve2026119618Detector.isSupportedService(
                buildHttpService("127.0.0.1", 8080, "tcpwrapped")))
        .isTrue();
    assertThat(
            Cve2026119618Detector.isSupportedService(
                buildHttpService("127.0.0.1", 22, "tcpwrapped")))
        .isFalse();
    assertThat(Cve2026119618Detector.isSupportedService(buildHttpService("127.0.0.1", 8080, "ssh")))
        .isFalse();
    assertThat(
            Cve2026119618Detector.isSupportedService(
                buildHttpService("127.0.0.1", 10443, "http over ssl")))
        .isTrue();
    assertThat(
            Cve2026119618Detector.preferredTransports(
                buildHttpService("127.0.0.1", 8443, "tcpwrapped")))
        .containsExactly(TransportMode.H2_TLS, TransportMode.H2C)
        .inOrder();
    assertThat(
            Cve2026119618Detector.preferredTransports(
                buildHttpService("127.0.0.1", 8080, "tcpwrapped")))
        .containsExactly(TransportMode.H2C, TransportMode.H2_TLS)
        .inOrder();

    // Verify IPv6 bracketed :authority and Host + crawled same-origin path fallback when / returns
    // 404.
    List<RecordedStream> recorded = Collections.synchronizedList(new ArrayList<>());
    MockApacheConfig cfg =
        MockApacheConfig.vulnerableTraceEnableOn()
            .withRouteStatus("/", "404")
            .withRouteStatus("/first", "403");

    Cve2026119618Detector detector =
        newDetector((mode, host, port, sniHost, timeout) -> {
          if (mode == TransportMode.H2_TLS) {
            throw new IOException("h2c only");
          }
          return startMockApachePeer(cfg, recorded);
        });

    NetworkService ipv6Svc =
        NetworkService.newBuilder()
            .setTransportProtocol(TransportProtocol.TCP)
            .setServiceName("http")
            .setNetworkEndpoint(
                NetworkEndpoint.newBuilder()
                    .setIpAddress(IpAddress.newBuilder().setAddress("2001:db8::1"))
                    .setPort(Port.newBuilder().setPortNumber(8080)))
            .setServiceContext(
                ServiceContext.newBuilder()
                    .setWebServiceContext(
                        WebServiceContext.newBuilder()
                            .addCrawlResults(
                                CrawlResult.newBuilder()
                                    .setCrawlTarget(
                                        CrawlTarget.newBuilder()
                                            .setUrl("https://cdn.external.example/evil")))
                            .addCrawlResults(
                                CrawlResult.newBuilder()
                                    .setCrawlTarget(
                                        CrawlTarget.newBuilder()
                                            .setUrl("http://[2001:db8::1]:8080/first#frag")))
                            .addCrawlResults(
                                CrawlResult.newBuilder()
                                    .setCrawlTarget(
                                        CrawlTarget.newBuilder()
                                            .setUrl(
                                                "http://[2001:db8::1]:8080/second?ok=1#frag")))))
            .build();

    DetectionReportList reports =
        detector.detect(buildTargetInfo(ipv6Svc.getNetworkEndpoint()), ImmutableList.of(ipv6Svc));

    assertThat(reports.getDetectionReportsList()).hasSize(1);
    assertThat(
            reports
                .getDetectionReports(0)
                .getVulnerability()
                .getAdditionalDetails(0)
                .getTextData()
                .getText())
        .contains("http://[2001:db8::1]:8080/second?ok=1:");

    // Also verify H2ProbeSession frame-helper, HpackCodec Huffman, and TraceEchoParser bounds
    // directly.
    assertThrows(
        IOException.class,
        () ->
            H2ProbeSession.readFrameHeader(
                new ByteArrayInputStream(new byte[] {0, 0, 1, 0, 0}))); // truncated 5-byte header
    FrameHeader masked =
        H2ProbeSession.readFrameHeader(
            new ByteArrayInputStream(new byte[] {0, 1, 2, 1, 0, (byte) 0x80, 0, 0, 5}));
    assertThat(masked.length).isEqualTo(258);
    assertThat(masked.streamId).isEqualTo(5);
    assertThrows(
        IOException.class,
        () ->
            H2ProbeSession.readFrameHeader(
                new ByteArrayInputStream(new byte[] {1, 0, 0, 1, 0, 0, 0, 0, 1})));
    assertThat(TraceEchoParser.sanitizeRequestPath("\u007fbad")).isEmpty();
    assertThat(HpackCodec.decodeHuffman(new byte[] {(byte) 0xff, (byte) 0xc7}))
        .isEqualTo(new byte[] {0});
    assertThat(HpackCodec.decodeHuffman(new byte[] {(byte) 0xff, (byte) 0xcf}))
        .isEqualTo(new byte[] {'$'});
    assertThrows(IOException.class, () -> HpackCodec.decodeHuffman(new byte[] {0x01}));
    ByteArrayOutputStream sixteenContinuations = new ByteArrayOutputStream();
    for (int i = 0; i < H2ProbeSession.MAX_CONTINUATION_FRAMES; i++) {
      int flags =
          (i == H2ProbeSession.MAX_CONTINUATION_FRAMES - 1) ? H2ProbeSession.FLAG_END_HEADERS : 0;
      H2ProbeSession.writeRawFrame(
          sixteenContinuations, H2ProbeSession.FRAME_CONTINUATION, flags, 1, new byte[] {1});
    }
    assertThat(
            H2ProbeSession.readContinuations(
                new ByteArrayInputStream(sixteenContinuations.toByteArray()), 1, new byte[] {0}))
        .hasLength(1 + H2ProbeSession.MAX_CONTINUATION_FRAMES);
    assertThrows(
        IOException.class,
        () ->
            H2ProbeSession.stripHeadersPaddingAndPriority(new byte[0], H2ProbeSession.FLAG_PADDED));
    assertThrows(
        IOException.class,
        () ->
            H2ProbeSession.stripHeadersPaddingAndPriority(
                new byte[] {10, 0, 0}, H2ProbeSession.FLAG_PADDED));
    assertThrows(
        IOException.class,
        () -> H2ProbeSession.stripDataPadding(new byte[0], H2ProbeSession.FLAG_PADDED));
    assertThrows(
        IOException.class,
        () -> H2ProbeSession.stripDataPadding(new byte[] {2, 'a'}, H2ProbeSession.FLAG_PADDED));

    // Verify @Inject constructor (including randomHexNonce), unsupported service skip, and empty
    // endpoint handling inside detect().
    TsunamiSocketFactory injectFactory = mock(TsunamiSocketFactory.class);
    when(injectFactory.createSocket(anyString(), anyInt(), any(Duration.class)))
        .thenAnswer(
            inv -> startMockApachePeer(MockApacheConfig.vulnerableTraceEnableOn(), recorded));
    Cve2026119618Detector injectedDetector = new Cve2026119618Detector(fakeUtcClock, injectFactory);
    NetworkService udpSvc =
        NetworkService.newBuilder()
            .setTransportProtocol(TransportProtocol.UDP)
            .setServiceName("http")
            .build();
    NetworkService emptyEpSvc =
        NetworkService.newBuilder()
            .setTransportProtocol(TransportProtocol.TCP)
            .setServiceName("http")
            .build();
    NetworkService validH2cSvc = buildHttpService("127.0.0.1", 80, "http");
    DetectionReportList mixedReports =
        injectedDetector.detect(
            buildTargetInfo(validH2cSvc.getNetworkEndpoint()),
            ImmutableList.of(udpSvc, emptyEpSvc, validH2cSvc));
    assertThat(mixedReports.getDetectionReportsList()).hasSize(1);
    assertThat(
            mixedReports
                .getDetectionReports(0)
                .getVulnerability()
                .getAdditionalDetails(0)
                .getTextData()
                .getText())
        .contains("http://127.0.0.1/:");
  }

  @Test
  public void h2ProbeSession_handlesMultiChunkDataSettingsRstUnknownFramesAndLimits()
      throws Exception {
    ImmutableList<HeaderField> reqHeaders =
        ImmutableList.of(
            new HeaderField(":method", "TRACE"),
            new HeaderField(":scheme", "http"),
            new HeaderField(":authority", "127.0.0.1:8080"),
            new HeaderField(":path", "/"));

    // 1. Multi-chunk DATA (triggers WINDOW_UPDATE), 103 Early Hints interim HEADERS, mid-stream
    // non-ACK SETTINGS, unknown frame type 0xfe, unrelated stream 99 frames, and header ceiling
    // (>9 headers) check.
    TransportConnector richConnector =
        (mode, host, port, sniHost, timeout) -> {
          InMemorySocketPair pair = InMemorySocketPair.create();
          serverExecutor.execute(() -> {
            try (Socket srv = pair.serverSocket) {
              InputStream in = srv.getInputStream();
              OutputStream out = srv.getOutputStream();
              in.readNBytes(clientPreface.length);
              writeFrame(out, H2ProbeSession.FRAME_SETTINGS, 0, 0, new byte[0]);
              HpackCodec.Decoder dec = new HpackCodec.Decoder(4096);
              RecordedStream req =
                  readNextRequestStream(in, out, dec, new byte[8], new AtomicBoolean());
              writeFrame(out, H2ProbeSession.FRAME_SETTINGS, 0, 0, new byte[6]);
              writeFrame(out, 0xfe, 0, 0, new byte[] {1, 2});
              writeFrame(
                  out,
                  H2ProbeSession.FRAME_HEADERS,
                  H2ProbeSession.FLAG_END_HEADERS,
                  99,
                  new byte[] {(byte) 0x88});
              writeFrame(out, H2ProbeSession.FRAME_DATA, 0, 99, new byte[] {'z'});
              writeFrame(out, H2ProbeSession.FRAME_RST_STREAM, 0, 99, new byte[] {0, 0, 0, 8});
              byte[] earlyHintsBlock =
                  HpackCodec.encodeLiteralNeverIndexed(
                      ImmutableList.of(
                          new HeaderField(":status", "103"),
                          new HeaderField("link", "</app.css>; rel=preload")));
              writeFrame(
                  out,
                  H2ProbeSession.FRAME_HEADERS,
                  H2ProbeSession.FLAG_END_HEADERS,
                  req.streamId,
                  earlyHintsBlock);
              writeFrame(
                  out,
                  H2ProbeSession.FRAME_HEADERS,
                  H2ProbeSession.FLAG_END_HEADERS,
                  req.streamId,
                  new byte[] {(byte) 0x88});
              writeFrame(
                  out, H2ProbeSession.FRAME_DATA, 0, req.streamId, " chunk1-".getBytes(ISO_8859_1));
              writeFrame(
                  out,
                  H2ProbeSession.FRAME_DATA,
                  H2ProbeSession.FLAG_END_STREAM,
                  req.streamId,
                  "chunk2".getBytes(ISO_8859_1));
              while (in.read() != -1) {
                // Drain client SETTINGS ACK / WINDOW_UPDATE until session closes.
              }
            } catch (IOException ignored) {
              // Expected on close.
            }
          });
          return pair.clientSocket;
        };

    try (H2ProbeSession session =
        H2ProbeSession.open(
            richConnector, TransportMode.H2C, "127.0.0.1", 8080, "", Duration.ofSeconds(2))) {
      assertThrows(
          IOException.class,
          () -> session.roundTrip(Collections.nCopies(10, new HeaderField("a", "b")), new byte[0]));
      H2ProbeSession.H2Response resp = session.roundTrip(reqHeaders, new byte[0]);
      assertThat(resp.status).isEqualTo("200");
      assertThat(new String(resp.body, ISO_8859_1)).isEqualTo(" chunk1-chunk2");
    }

    // 2. Malformed frames (SETTINGS len=5, PING len=4, GOAWAY len=4, stray CONTINUATION,
    // RST_STREAM before headers, >65536 body, and >64 frames) all throw IOException cleanly.
    ImmutableList<PeerScript> errorScripts =
        ImmutableList.of(
            (in, out) -> {
              in.readNBytes(clientPreface.length);
              writeFrame(out, H2ProbeSession.FRAME_SETTINGS, 0, 0, new byte[0]);
              assertThat(
                      readNextRequestStream(
                              in,
                              out,
                              new HpackCodec.Decoder(4096),
                              new byte[8],
                              new AtomicBoolean())
                          .streamId)
                  .isEqualTo(1);
              writeFrame(out, H2ProbeSession.FRAME_SETTINGS, 0, 0, new byte[5]);
            },
            (in, out) -> {
              in.readNBytes(clientPreface.length);
              writeFrame(out, H2ProbeSession.FRAME_SETTINGS, 0, 0, new byte[0]);
              assertThat(
                      readNextRequestStream(
                              in,
                              out,
                              new HpackCodec.Decoder(4096),
                              new byte[8],
                              new AtomicBoolean())
                          .streamId)
                  .isEqualTo(1);
              writeFrame(out, H2ProbeSession.FRAME_PING, 0, 0, new byte[4]);
            },
            (in, out) -> {
              in.readNBytes(clientPreface.length);
              writeFrame(out, H2ProbeSession.FRAME_SETTINGS, 0, 0, new byte[0]);
              assertThat(
                      readNextRequestStream(
                              in,
                              out,
                              new HpackCodec.Decoder(4096),
                              new byte[8],
                              new AtomicBoolean())
                          .streamId)
                  .isEqualTo(1);
              writeFrame(out, H2ProbeSession.FRAME_GOAWAY, 0, 0, new byte[4]);
            },
            (in, out) -> {
              in.readNBytes(clientPreface.length);
              writeFrame(out, H2ProbeSession.FRAME_SETTINGS, 0, 0, new byte[0]);
              RecordedStream req =
                  readNextRequestStream(
                      in, out, new HpackCodec.Decoder(4096), new byte[8], new AtomicBoolean());
              writeFrame(out, H2ProbeSession.FRAME_CONTINUATION, 0, req.streamId, new byte[0]);
            },
            (in, out) -> {
              in.readNBytes(clientPreface.length);
              writeFrame(out, H2ProbeSession.FRAME_SETTINGS, 0, 0, new byte[0]);
              RecordedStream req =
                  readNextRequestStream(
                      in, out, new HpackCodec.Decoder(4096), new byte[8], new AtomicBoolean());
              writeFrame(
                  out, H2ProbeSession.FRAME_RST_STREAM, 0, req.streamId, new byte[] {0, 0, 0, 2});
            },
            (in, out) -> {
              in.readNBytes(clientPreface.length);
              writeFrame(out, H2ProbeSession.FRAME_SETTINGS, 0, 0, new byte[0]);
              RecordedStream req =
                  readNextRequestStream(
                      in, out, new HpackCodec.Decoder(4096), new byte[8], new AtomicBoolean());
              writeFrame(
                  out,
                  H2ProbeSession.FRAME_HEADERS,
                  H2ProbeSession.FLAG_END_HEADERS,
                  req.streamId,
                  new byte[] {(byte) 0x88});
              byte[] chunk = new byte[16384];
              for (int i = 0; i < 3; i++) {
                writeFrame(out, H2ProbeSession.FRAME_DATA, 0, req.streamId, chunk);
              }
              writeFrame(out, H2ProbeSession.FRAME_DATA, 0, req.streamId, new byte[16383]);
              // Enforce RFC 9113 initial 65,535-byte stream window: wait for stream-level
              // WINDOW_UPDATE on req.streamId before sending bytes > 65,536.
              while (true) {
                FrameHeader wfh = H2ProbeSession.readFrameHeader(in);
                byte[] wp = in.readNBytes(wfh.length);
                if (wfh.type == H2ProbeSession.FRAME_WINDOW_UPDATE
                    && wfh.streamId == req.streamId
                    && wp.length == 4) {
                  break;
                }
              }
              writeFrame(
                  out,
                  H2ProbeSession.FRAME_DATA,
                  H2ProbeSession.FLAG_END_STREAM,
                  req.streamId,
                  new byte[] {'B', 'B'});
            },
            (in, out) -> {
              in.readNBytes(clientPreface.length);
              writeFrame(out, H2ProbeSession.FRAME_SETTINGS, 0, 0, new byte[0]);
              assertThat(
                      readNextRequestStream(
                              in,
                              out,
                              new HpackCodec.Decoder(4096),
                              new byte[8],
                              new AtomicBoolean())
                          .streamId)
                  .isEqualTo(1);
              out.close();
            },
            (in, out) -> {
              in.readNBytes(clientPreface.length);
              writeFrame(out, H2ProbeSession.FRAME_SETTINGS, 0, 0, new byte[0]);
              assertThat(
                      readNextRequestStream(
                              in,
                              out,
                              new HpackCodec.Decoder(4096),
                              new byte[8],
                              new AtomicBoolean())
                          .streamId)
                  .isEqualTo(1);
              // readNextRequestStream writes 1 SETTINGS ACK frame, so MAX_FRAMES_PER_STREAM - 1
              // WINDOW_UPDATE frames + 1 HEADERS frame = MAX_FRAMES_PER_STREAM + 1 total frames.
              for (int i = 0; i < H2ProbeSession.MAX_FRAMES_PER_STREAM - 1; i++) {
                writeFrame(out, H2ProbeSession.FRAME_WINDOW_UPDATE, 0, 0, new byte[] {0, 0, 0, 1});
              }
              writeFrame(
                  out,
                  H2ProbeSession.FRAME_HEADERS,
                  H2ProbeSession.FLAG_END_HEADERS | H2ProbeSession.FLAG_END_STREAM,
                  1,
                  new byte[] {(byte) 0x88});
            });

    for (PeerScript script : errorScripts) {
      AtomicReference<Future<?>> serverFuture = new AtomicReference<>();
      AtomicReference<PipeSocket> clientSocketRef = new AtomicReference<>();
      AtomicInteger errConns = new AtomicInteger(0);
      TransportConnector errConnector =
          (mode, host, port, sniHost, timeout) -> {
            errConns.incrementAndGet();
            InMemorySocketPair pair = InMemorySocketPair.create();
            clientSocketRef.set(pair.clientSocket);
            serverFuture.set(
                serverExecutor.submit(() -> {
                  try (Socket srv = pair.serverSocket) {
                    script.run(srv.getInputStream(), srv.getOutputStream());
                  } catch (IOException | InterruptedException ignored) {
                    // Expected on error close.
                  }
                }));
            return pair.clientSocket;
          };
      try (H2ProbeSession session =
          H2ProbeSession.open(
              errConnector, TransportMode.H2C, "127.0.0.1", 8080, "", Duration.ofSeconds(2))) {
        assertThrows(IOException.class, () -> session.roundTrip(reqHeaders, new byte[0]));
        session.close();
      }
      assertThat(errConns.get()).isEqualTo(1);
      assertThat(clientSocketRef.get().isClosed()).isTrue();
      assertThat(clientSocketRef.get().closeCount()).isEqualTo(1);
      serverFuture.get().get(2, SECONDS);
    }

    // Exact MAX_FRAMES_PER_STREAM boundary: MAX_FRAMES_PER_STREAM - 1 WINDOW_UPDATE frames
    // followed by the final HEADERS frame at frameCount == MAX_FRAMES_PER_STREAM - 1 must succeed.
    TransportConnector exactMaxFramesConnector =
        (mode, host, port, sniHost, timeout) -> {
          InMemorySocketPair pair = InMemorySocketPair.create();
          serverExecutor.execute(() -> {
            try (Socket srv = pair.serverSocket) {
              InputStream in = srv.getInputStream();
              OutputStream out = srv.getOutputStream();
              in.readNBytes(clientPreface.length);
              writeFrame(out, H2ProbeSession.FRAME_SETTINGS, 0, 0, new byte[0]);
              RecordedStream req =
                  readNextRequestStream(
                      in, out, new HpackCodec.Decoder(4096), new byte[8], new AtomicBoolean());
              // readNextRequestStream already writes 1 SETTINGS ACK frame (frameCount == 0), so
              // MAX_FRAMES_PER_STREAM - 2 WINDOW_UPDATE frames + 1 HEADERS frame =
              // MAX_FRAMES_PER_STREAM frames total (landing at frameCount == MAX_FRAMES_PER_STREAM
              // - 1).
              for (int i = 0; i < H2ProbeSession.MAX_FRAMES_PER_STREAM - 2; i++) {
                writeFrame(out, H2ProbeSession.FRAME_WINDOW_UPDATE, 0, 0, new byte[] {0, 0, 0, 1});
              }
              writeFrame(
                  out,
                  H2ProbeSession.FRAME_HEADERS,
                  H2ProbeSession.FLAG_END_HEADERS | H2ProbeSession.FLAG_END_STREAM,
                  req.streamId,
                  new byte[] {(byte) 0x88});
            } catch (IOException ignored) {
              // Expected on close.
            }
          });
          return pair.clientSocket;
        };
    try (H2ProbeSession session =
        H2ProbeSession.open(
            exactMaxFramesConnector,
            TransportMode.H2C,
            "127.0.0.1",
            8080,
            "",
            Duration.ofSeconds(2))) {
      assertThat(session.roundTrip(reqHeaders, new byte[0]).status).isEqualTo("200");
    }
  }

  private Cve2026119618Detector newDetector(TransportConnector connector) {
    return new Cve2026119618Detector(
        fakeUtcClock, connector, Duration.ofSeconds(2), sequentialNonceSupplier());
  }

  private static Supplier<String> sequentialNonceSupplier() {
    AtomicInteger idx = new AtomicInteger(0);
    return () -> String.format("000000000000000%d", idx.incrementAndGet());
  }

  private Socket startMockApachePeer(MockApacheConfig cfg, List<RecordedStream> recorded)
      throws IOException {
    InMemorySocketPair pair = InMemorySocketPair.create();
    serverExecutor.execute(() -> {
      try (Socket srv = pair.serverSocket) {
        serveMockApacheH2(srv, cfg, recorded);
      } catch (IOException ignored) {
        // Expected when client closes session.
      }
    });
    return pair.clientSocket;
  }

  private static void serveMockApacheH2(
      Socket srv, MockApacheConfig cfg, List<RecordedStream> recorded) throws IOException {
    InputStream in = srv.getInputStream();
    OutputStream out = srv.getOutputStream();
    byte[] preface = in.readNBytes(clientPreface.length);
    if (!Arrays.equals(preface, clientPreface)) {
      return;
    }
    // Verify client sends its initial empty SETTINGS frame immediately after the connection
    // preface.
    FrameHeader clientSettings = H2ProbeSession.readFrameHeader(in);
    if (clientSettings.type != H2ProbeSession.FRAME_SETTINGS
        || (clientSettings.flags & H2ProbeSession.FLAG_ACK) != 0
        || clientSettings.streamId != 0
        || clientSettings.length != 0) {
      return;
    }
    // Send a 6-byte server SETTINGS frame (SETTINGS_MAX_CONCURRENT_STREAMS = 100) so the client
    // must skip firstHdr.length bytes and reply with a SETTINGS ACK frame.
    writeFrame(out, H2ProbeSession.FRAME_SETTINGS, 0, 0, new byte[] {0, 3, 0, 0, 0, 100});
    writeFrame(out, H2ProbeSession.FRAME_SETTINGS, H2ProbeSession.FLAG_ACK, 0, new byte[0]);
    FrameHeader clientAck = H2ProbeSession.readFrameHeader(in);
    if (clientAck.type != H2ProbeSession.FRAME_SETTINGS
        || (clientAck.flags & H2ProbeSession.FLAG_ACK) == 0
        || clientAck.streamId != 0
        || clientAck.length != 0) {
      return;
    }
    HpackCodec.Decoder reqDec = new HpackCodec.Decoder(4096);
    AtomicBoolean indexedCt = new AtomicBoolean(false);
    while (true) {
      RecordedStream req = readNextRequestStream(in, out, reqDec, new byte[8], new AtomicBoolean());
      recorded.add(req);
      writeMockApacheResponse(out, req, indexedCt, cfg);
    }
  }

  private static void serveMockApacheH2WithFirstByte(
      Socket srv, byte firstByte, MockApacheConfig cfg, List<RecordedStream> recorded)
      throws IOException {
    InputStream rawIn = srv.getInputStream();
    byte[] rest = rawIn.readNBytes(clientPreface.length - 1);
    byte[] preface = new byte[clientPreface.length];
    preface[0] = firstByte;
    System.arraycopy(rest, 0, preface, 1, rest.length);
    if (!Arrays.equals(preface, clientPreface)) {
      return;
    }
    OutputStream out = srv.getOutputStream();
    writeFrame(out, H2ProbeSession.FRAME_SETTINGS, 0, 0, new byte[0]);
    HpackCodec.Decoder reqDec = new HpackCodec.Decoder(4096);
    AtomicBoolean indexedCt = new AtomicBoolean(false);
    while (true) {
      RecordedStream req =
          readNextRequestStream(rawIn, out, reqDec, new byte[8], new AtomicBoolean());
      recorded.add(req);
      writeMockApacheResponse(out, req, indexedCt, cfg);
    }
  }

  private static RecordedStream readNextRequestStream(
      InputStream in,
      OutputStream out,
      HpackCodec.Decoder reqDec,
      byte[] expectedPing,
      AtomicBoolean sawPingAck)
      throws IOException {
    while (true) {
      FrameHeader fh = H2ProbeSession.readFrameHeader(in);
      byte[] payload = in.readNBytes(fh.length);
      if (fh.type == H2ProbeSession.FRAME_SETTINGS && (fh.flags & H2ProbeSession.FLAG_ACK) == 0) {
        writeFrame(out, H2ProbeSession.FRAME_SETTINGS, H2ProbeSession.FLAG_ACK, 0, new byte[0]);
      } else if (fh.type == H2ProbeSession.FRAME_PING
          && (fh.flags & H2ProbeSession.FLAG_ACK) != 0
          && Arrays.equals(payload, expectedPing)) {
        sawPingAck.set(true);
      } else if (fh.type == H2ProbeSession.FRAME_DATA) {
        throw new IOException("Unexpected DATA frame outside active stream: " + fh.streamId);
      } else if (fh.type == H2ProbeSession.FRAME_HEADERS) {
        ImmutableList<HeaderField> hdrs = reqDec.decodeHeaderBlock(payload);
        boolean endStream = (fh.flags & H2ProbeSession.FLAG_END_STREAM) != 0;
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        while (!endStream) {
          FrameHeader dfh = H2ProbeSession.readFrameHeader(in);
          byte[] dp = in.readNBytes(dfh.length);
          if (dfh.type == H2ProbeSession.FRAME_PING
              && (dfh.flags & H2ProbeSession.FLAG_ACK) != 0
              && Arrays.equals(dp, expectedPing)) {
            sawPingAck.set(true);
          } else if (dfh.type == H2ProbeSession.FRAME_DATA && dfh.streamId == fh.streamId) {
            if (dfh.length == 0) {
              throw new IOException("Unexpected 0-byte DATA frame on stream " + fh.streamId);
            }
            body.writeBytes(dp);
            endStream = (dfh.flags & H2ProbeSession.FLAG_END_STREAM) != 0;
          }
        }
        return new RecordedStream(fh.streamId, hdrs, body.toByteArray());
      }
    }
  }

  private static void readNextRequestStreamOrAck(
      InputStream in, byte[] expectedPing, AtomicBoolean sawPingAck) throws IOException {
    FrameHeader fh = H2ProbeSession.readFrameHeader(in);
    byte[] payload = in.readNBytes(fh.length);
    if (fh.type == H2ProbeSession.FRAME_PING
        && (fh.flags & H2ProbeSession.FLAG_ACK) != 0
        && Arrays.equals(payload, expectedPing)) {
      sawPingAck.set(true);
    }
  }

  private static void writeMockApacheResponse(
      OutputStream out, RecordedStream req, AtomicBoolean indexedCt, MockApacheConfig cfg)
      throws IOException {
    Map<String, String> hm = req.headerMap();
    String path = hm.get(":path");
    String authority = hm.get(":authority");
    String probe = hm.get("x-tsunami-probe");
    String explicitCl = hm.get("content-length");

    if (cfg.routeStatuses.containsKey(path)) {
      byte[] hdr =
          HpackCodec.encodeLiteralNeverIndexed(
              ImmutableList.of(new HeaderField(":status", cfg.routeStatuses.get(path))));
      writeFrame(
          out,
          H2ProbeSession.FRAME_HEADERS,
          H2ProbeSession.FLAG_END_HEADERS | H2ProbeSession.FLAG_END_STREAM,
          req.streamId,
          hdr);
      return;
    }

    if (explicitCl == null && cfg.stream1Status != null) {
      byte[] hdr =
          HpackCodec.encodeLiteralNeverIndexed(
              ImmutableList.of(new HeaderField(":status", cfg.stream1Status)));
      writeFrame(
          out,
          H2ProbeSession.FRAME_HEADERS,
          H2ProbeSession.FLAG_END_HEADERS | H2ProbeSession.FLAG_END_STREAM,
          req.streamId,
          hdr);
      return;
    }

    if (Objects.equals(explicitCl, "0") && cfg.stream3Status != null) {
      byte[] hdr =
          HpackCodec.encodeLiteralNeverIndexed(
              ImmutableList.of(new HeaderField(":status", cfg.stream3Status)));
      writeFrame(
          out,
          H2ProbeSession.FRAME_HEADERS,
          H2ProbeSession.FLAG_END_HEADERS | H2ProbeSession.FLAG_END_STREAM,
          req.streamId,
          hdr);
      return;
    }

    // Stream 5 (1-byte body control).
    if (Objects.equals(explicitCl, "1") || req.body.length > 0) {
      if (!cfg.stream5Extended) {
        String status = cfg.stream5Status != null ? cfg.stream5Status : "413";
        byte[] hdr =
            HpackCodec.encodeLiteralNeverIndexed(
                ImmutableList.of(new HeaderField(":status", status)));
        writeFrame(
            out, H2ProbeSession.FRAME_HEADERS, H2ProbeSession.FLAG_END_HEADERS, req.streamId, hdr);
        writeFrame(
            out,
            H2ProbeSession.FRAME_DATA,
            0,
            req.streamId,
            "413 Request Entity Too Large".getBytes(ISO_8859_1));
        // Trailing RST_STREAM(NO_ERROR) terminating early 413 response (kills MT-2 #3!).
        writeFrame(out, H2ProbeSession.FRAME_RST_STREAM, 0, req.streamId, new byte[] {0, 0, 0, 0});
        return;
      }
    }

    String protoVer = cfg.http11EchoLine ? "HTTP/1.1" : "HTTP/2.0";
    String hostKey = cfg.lowercaseHostEcho ? "host" : "Host";
    String probeKey = cfg.lowercaseProbeEcho ? "x-tsunami-probe" : "X-Tsunami-Probe";

    StringBuilder echo = new StringBuilder();
    echo.append("TRACE ").append(path).append(' ').append(protoVer).append("\r\n");
    echo.append(hostKey).append(": ").append(authority).append("\r\n");
    if (hm.containsKey("content-type")) {
      echo.append("Content-Type: ").append(hm.get("content-type")).append("\r\n");
    }
    if (explicitCl == null) {
      if (cfg.stream1ContentLengthKey != null) {
        echo.append(cfg.stream1ContentLengthKey).append(": 0\r\n");
      }
    } else if (Objects.equals(explicitCl, "0")) {
      if (!cfg.omitStream3ContentLength) {
        echo.append("Content-Length: 0\r\n");
      }
    } else if (Objects.equals(explicitCl, "1")) {
      if (!cfg.omitStream5ContentLength) {
        echo.append("Content-Length: 1\r\n");
      }
    }
    String echoedProbe = Objects.equals(explicitCl, "0") && cfg.stream3BadNonce ? "bad" : probe;
    echo.append(probeKey).append(": ").append(echoedProbe).append("\r\n\r\n");
    if (Objects.equals(explicitCl, "1") && cfg.stream5Extended && !cfg.omitStream5Body) {
      echo.append(new String(req.body, ISO_8859_1));
    }

    if ((explicitCl == null && cfg.malformedStream1Body)
        || (Objects.equals(explicitCl, "0") && cfg.malformedStream3Body)
        || (Objects.equals(explicitCl, "1") && cfg.malformedStream5Body)) {
      echo.setLength(0);
      echo.append("UNTERMINATED_TRACE_ECHO_WITHOUT_BLANK_LINE");
    }

    // Dynamic table indexing on Stream 1 (0x5f -> index 62) and indexed lookup 0xbe on Streams 3 &
    // 5!
    ByteArrayOutputStream hblock = new ByteArrayOutputStream();
    boolean isStream5 = Objects.equals(explicitCl, "1") || req.body.length > 0;
    String status = isStream5 && cfg.stream5Status != null ? cfg.stream5Status : "200";
    if (status.equals("200")) {
      hblock.write(0x88); // :status = 200
    } else {
      hblock.writeBytes(
          HpackCodec.encodeLiteralNeverIndexed(
              ImmutableList.of(new HeaderField(":status", status))));
    }
    String customCt =
        isStream5 && cfg.stream5ContentType != null
            ? cfg.stream5ContentType
            : cfg.responseContentType;
    if (customCt != null) {
      byte[] custom =
          HpackCodec.encodeLiteralNeverIndexed(
              ImmutableList.of(new HeaderField("content-type", customCt)));
      hblock.writeBytes(custom);
    } else if (indexedCt.compareAndSet(false, true)) {
      byte[] ctVal = "message/http; charset=UTF-8".getBytes(ISO_8859_1);
      hblock.write(0x5f); // Literal with Incremental Indexing, name index 31 (content-type)
      hblock.write(ctVal.length);
      hblock.writeBytes(ctVal);
    } else {
      hblock.write(0xbe); // Indexed dynamic table entry 62 (kills MT-2 #1!)
    }

    writeFrame(
        out,
        H2ProbeSession.FRAME_HEADERS,
        H2ProbeSession.FLAG_END_HEADERS,
        req.streamId,
        hblock.toByteArray());
    writeFrame(
        out,
        H2ProbeSession.FRAME_DATA,
        H2ProbeSession.FLAG_END_STREAM,
        req.streamId,
        echo.toString().getBytes(ISO_8859_1));
  }

  private static void writeFrame(
      OutputStream out, int type, int flags, int streamIdWithOptionalMsb, byte[] payload)
      throws IOException {
    ByteArrayOutputStream buf = new ByteArrayOutputStream(9 + payload.length);
    int len = payload.length;
    buf.write((len >>> 16) & 0xff);
    buf.write((len >>> 8) & 0xff);
    buf.write(len & 0xff);
    buf.write(type & 0xff);
    buf.write(flags & 0xff);
    buf.write((streamIdWithOptionalMsb >>> 24) & 0xff);
    buf.write((streamIdWithOptionalMsb >>> 16) & 0xff);
    buf.write((streamIdWithOptionalMsb >>> 8) & 0xff);
    buf.write(streamIdWithOptionalMsb & 0xff);
    buf.writeBytes(payload);
    buf.writeTo(out);
    out.flush();
  }

  private static NetworkService buildHttpService(String ip, int port, String serviceName) {
    return NetworkService.newBuilder()
        .setTransportProtocol(TransportProtocol.TCP)
        .setServiceName(serviceName)
        .setNetworkEndpoint(
            NetworkEndpoint.newBuilder()
                .setIpAddress(IpAddress.newBuilder().setAddress(ip))
                .setPort(Port.newBuilder().setPortNumber(port)))
        .build();
  }

  private static TargetInfo buildTargetInfo(NetworkEndpoint endpoint) {
    return TargetInfo.newBuilder().addNetworkEndpoints(endpoint).build();
  }

  private static DetectionReport expectedReport(
      TargetInfo targetInfo, NetworkService service, String detailText) {
    return DetectionReport.newBuilder()
        .setTargetInfo(targetInfo)
        .setNetworkService(service)
        .setDetectionTimestamp(Timestamps.fromMillis(FIXED_INSTANT.toEpochMilli()))
        .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
        .setVulnerability(
            Vulnerability.newBuilder()
                .setMainId(
                    VulnerabilityId.newBuilder()
                        .setPublisher(Cve2026119618Detector.VULN_REPORT_PUBLISHER)
                        .setValue(Cve2026119618Detector.VULN_REPORT_ID))
                .addRelatedId(
                    VulnerabilityId.newBuilder().setPublisher("CVE").setValue("CVE-2026-119618"))
                .setSeverity(Severity.CRITICAL)
                .setTitle(Cve2026119618Detector.VULN_REPORT_TITLE)
                .setDescription(Cve2026119618Detector.VULN_DESCRIPTION)
                .setRecommendation(Cve2026119618Detector.VULN_RECOMMENDATION)
                .addAdditionalDetails(
                    AdditionalDetail.newBuilder()
                        .setDescription(Cve2026119618Detector.DETECTION_EVIDENCE_DESCRIPTION)
                        .setTextData(TextData.newBuilder().setText(detailText))))
        .build();
  }

  private static SSLSocket wrapServerTls(SSLContext sslContext, Socket rawSocket, String[] alpn)
      throws IOException {
    SSLSocket sslSocket =
        (SSLSocket) sslContext.getSocketFactory().createSocket(rawSocket, "127.0.0.1", 8443, true);
    sslSocket.setUseClientMode(false);
    SSLParameters params = sslSocket.getSSLParameters();
    if (alpn.length > 0) {
      params.setApplicationProtocols(alpn);
    }
    sslSocket.setSSLParameters(params);
    return sslSocket;
  }

  /**
   * Generates an ephemeral in-memory self-signed ECDSA X.509 certificate and {@link SSLContext} at
   * test runtime using standard JCA APIs (zero hardcoded private keys or internal JDK packages).
   */
  private static SSLContext createSelfSignedServerSslContext()
      throws GeneralSecurityException, IOException {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
    kpg.initialize(new ECGenParameterSpec("secp256r1"));
    KeyPair kp = kpg.generateKeyPair();

    // AlgorithmIdentifier for ecdsa-with-SHA256 (1.2.840.10045.4.3.2)
    byte[] algId = BaseEncoding.base16().lowerCase().decode("300a06082a8648ce3d040302");
    // X.500 Name: CN=test
    byte[] name = BaseEncoding.base16().lowerCase().decode("300f310d300b06035504030c0474657374");
    byte[] validity =
        derSequence(
            derTag(0x17, "250101000000Z".getBytes(ISO_8859_1)),
            derTag(0x17, "350101000000Z".getBytes(ISO_8859_1)));

    byte[] tbs =
        derSequence(
            new byte[] {(byte) 0xa0, 0x03, 0x02, 0x01, 0x02}, // version v3
            new byte[] {0x02, 0x01, 0x01}, // serialNumber 1
            algId,
            name,
            validity,
            name,
            kp.getPublic().getEncoded());

    Signature signer = Signature.getInstance("SHA256withECDSA");
    signer.initSign(kp.getPrivate());
    signer.update(tbs);
    byte[] sigBytes = signer.sign();

    byte[] bitStringPayload = new byte[sigBytes.length + 1];
    System.arraycopy(sigBytes, 0, bitStringPayload, 1, sigBytes.length);
    byte[] certDer = derSequence(tbs, algId, derTag(0x03, bitStringPayload));

    X509Certificate cert =
        (X509Certificate)
            CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(certDer));

    KeyStore ks = KeyStore.getInstance("PKCS12");
    ks.load(null, null);
    char[] password = new char[0];
    ks.setKeyEntry("srv", kp.getPrivate(), password, new Certificate[] {cert});

    KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
    kmf.init(ks, password);

    SSLContext ctx = SSLContext.getInstance("TLS");
    ctx.init(kmf.getKeyManagers(), null, new SecureRandom());
    return ctx;
  }

  private static byte[] derSequence(byte[]... elements) {
    ByteArrayOutputStream content = new ByteArrayOutputStream();
    for (byte[] el : elements) {
      content.writeBytes(el);
    }
    return derTag(0x30, content.toByteArray());
  }

  private static byte[] derTag(int tag, byte[] content) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    out.write(tag);
    int len = content.length;
    if (len < 128) {
      out.write(len);
    } else if (len < 256) {
      out.write(0x81);
      out.write(len);
    } else {
      out.write(0x82);
      out.write((len >>> 8) & 0xff);
      out.write(len & 0xff);
    }
    out.writeBytes(content);
    return out.toByteArray();
  }

  @FunctionalInterface
  private interface PeerScript {
    void run(InputStream in, OutputStream out) throws IOException, InterruptedException;
  }

  private static final class RecordedStream {
    final int streamId;
    final ImmutableList<HeaderField> headers;
    final byte[] body;

    RecordedStream(int streamId, ImmutableList<HeaderField> headers, byte[] body) {
      this.streamId = streamId;
      this.headers = headers;
      this.body = body;
    }

    Map<String, String> headerMap() {
      Map<String, String> map = new LinkedHashMap<>();
      for (HeaderField hf : headers) {
        map.put(hf.name, hf.value);
      }
      return map;
    }
  }

  private static final class MockApacheConfig {
    boolean stream5Extended;
    String stream1ContentLengthKey;
    boolean omitStream3ContentLength;
    boolean http11EchoLine;
    boolean lowercaseProbeEcho;
    boolean lowercaseHostEcho;
    boolean omitStream5Body;
    boolean omitStream5ContentLength;
    String stream1Status;
    String stream3Status;
    String stream5Status;
    String stream5ContentType;
    String responseContentType;
    boolean malformedStream1Body;
    boolean malformedStream3Body;
    boolean malformedStream5Body;
    boolean stream3BadNonce;
    final Map<String, String> routeStatuses = new LinkedHashMap<>();

    static MockApacheConfig vulnerableTraceEnableOn() {
      return new MockApacheConfig();
    }

    static MockApacheConfig vulnerableTraceEnableExtended() {
      MockApacheConfig c = new MockApacheConfig();
      c.stream5Extended = true;
      return c;
    }

    private MockApacheConfig copy() {
      MockApacheConfig c = new MockApacheConfig();
      c.stream5Extended = this.stream5Extended;
      c.stream1ContentLengthKey = this.stream1ContentLengthKey;
      c.omitStream3ContentLength = this.omitStream3ContentLength;
      c.http11EchoLine = this.http11EchoLine;
      c.lowercaseProbeEcho = this.lowercaseProbeEcho;
      c.lowercaseHostEcho = this.lowercaseHostEcho;
      c.omitStream5Body = this.omitStream5Body;
      c.omitStream5ContentLength = this.omitStream5ContentLength;
      c.stream1Status = this.stream1Status;
      c.stream3Status = this.stream3Status;
      c.stream5Status = this.stream5Status;
      c.stream5ContentType = this.stream5ContentType;
      c.responseContentType = this.responseContentType;
      c.malformedStream1Body = this.malformedStream1Body;
      c.malformedStream3Body = this.malformedStream3Body;
      c.malformedStream5Body = this.malformedStream5Body;
      c.stream3BadNonce = this.stream3BadNonce;
      c.routeStatuses.putAll(this.routeStatuses);
      return c;
    }

    MockApacheConfig withStream1ContentLength(String key) {
      MockApacheConfig c = copy();
      c.stream1ContentLengthKey = key;
      return c;
    }

    MockApacheConfig withOmitStream3ContentLength() {
      MockApacheConfig c = copy();
      c.omitStream3ContentLength = true;
      return c;
    }

    MockApacheConfig withHttp11EchoLine() {
      MockApacheConfig c = copy();
      c.http11EchoLine = true;
      return c;
    }

    MockApacheConfig withLowercaseProbeEcho() {
      MockApacheConfig c = copy();
      c.lowercaseProbeEcho = true;
      return c;
    }

    MockApacheConfig withLowercaseHostEcho() {
      MockApacheConfig c = copy();
      c.lowercaseHostEcho = true;
      return c;
    }

    MockApacheConfig withOmitStream5Body() {
      MockApacheConfig c = copy();
      c.omitStream5Body = true;
      return c;
    }

    MockApacheConfig withOmitStream5ContentLength() {
      MockApacheConfig c = copy();
      c.omitStream5ContentLength = true;
      return c;
    }

    MockApacheConfig withStream1Status(String status) {
      MockApacheConfig c = copy();
      c.stream1Status = status;
      return c;
    }

    MockApacheConfig withStream5Status(String status) {
      MockApacheConfig c = copy();
      c.stream5Status = status;
      return c;
    }

    MockApacheConfig withStream5ContentType(String ct) {
      MockApacheConfig c = copy();
      c.stream5ContentType = ct;
      return c;
    }

    MockApacheConfig withStream3Status(String status) {
      MockApacheConfig c = copy();
      c.stream3Status = status;
      return c;
    }

    MockApacheConfig withStream3BadNonce() {
      MockApacheConfig c = copy();
      c.stream3BadNonce = true;
      return c;
    }

    MockApacheConfig withMalformedStream1Body() {
      MockApacheConfig c = copy();
      c.malformedStream1Body = true;
      return c;
    }

    MockApacheConfig withMalformedStream3Body() {
      MockApacheConfig c = copy();
      c.malformedStream3Body = true;
      return c;
    }

    MockApacheConfig withMalformedStream5Body() {
      MockApacheConfig c = copy();
      c.malformedStream5Body = true;
      return c;
    }

    MockApacheConfig withResponseContentType(String ct) {
      MockApacheConfig c = copy();
      c.responseContentType = ct;
      return c;
    }

    MockApacheConfig withRouteStatus(String path, String status) {
      MockApacheConfig c = copy();
      c.routeStatuses.put(path, status);
      return c;
    }
  }

  private static final class InMemorySocketPair {
    final PipeSocket clientSocket;
    final PipeSocket serverSocket;

    private InMemorySocketPair(PipeSocket clientSocket, PipeSocket serverSocket) {
      this.clientSocket = clientSocket;
      this.serverSocket = serverSocket;
    }

    static InMemorySocketPair create() throws IOException {
      PipedInputStream clientIn = new PipedInputStream(65536);
      PipedOutputStream serverOut = new PipedOutputStream(clientIn);
      PipedInputStream serverIn = new PipedInputStream(65536);
      PipedOutputStream clientOut = new PipedOutputStream(serverIn);
      return new InMemorySocketPair(
          new PipeSocket(clientIn, clientOut), new PipeSocket(serverIn, serverOut));
    }
  }

  private static final class PipeSocket extends Socket {
    private final InputStream in;
    private final OutputStream out;
    private volatile boolean closed;
    private final AtomicInteger closeCounter = new AtomicInteger(0);

    PipeSocket(InputStream in, OutputStream out) {
      this.in = in;
      this.out = out;
    }

    @Override
    public InputStream getInputStream() {
      return in;
    }

    @Override
    public OutputStream getOutputStream() {
      return out;
    }

    @Override
    public boolean isConnected() {
      return !closed;
    }

    @Override
    public boolean isClosed() {
      return closed;
    }

    int closeCount() {
      return closeCounter.get();
    }

    @Override
    public synchronized void close() throws IOException {
      closeCounter.incrementAndGet();
      if (!closed) {
        closed = true;
        out.close();
        in.close();
      }
    }
  }
}
