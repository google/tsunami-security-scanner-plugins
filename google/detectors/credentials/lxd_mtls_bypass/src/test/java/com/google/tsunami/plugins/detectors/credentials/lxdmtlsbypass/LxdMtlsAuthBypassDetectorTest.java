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
package com.google.tsunami.plugins.detectors.credentials.lxdmtlsbypass;

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.common.collect.ImmutableList;
import com.google.tsunami.common.data.NetworkEndpointUtils;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.plugins.detectors.credentials.lxdmtlsbypass.LxdMtlsAuthBypassDetector.EphemeralIdentity;
import com.google.tsunami.plugins.detectors.credentials.lxdmtlsbypass.LxdMtlsAuthBypassDetector.FixedChainKeyManager;
import com.google.tsunami.plugins.detectors.credentials.lxdmtlsbypass.LxdMtlsAuthBypassDetector.PermissiveTrustManager;
import com.google.tsunami.plugins.detectors.credentials.lxdmtlsbypass.LxdMtlsAuthBypassDetector.ProbeResult;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.TransportProtocol;
import com.google.tsunami.proto.VulnerabilityId;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Arrays;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509TrustManager;
import org.jspecify.annotations.Nullable;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link LxdMtlsAuthBypassDetector}. */
@RunWith(JUnit4.class)
public final class LxdMtlsAuthBypassDetectorTest {

  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2026-11-08T00:00:00.00Z"));

  private LxdMtlsAuthBypassDetector detector;
  private ExecutorService executor;
  private SSLServerSocket serverSocket;

  private enum ServerMode {
    VULNERABLE_CHAIN_LOOP,
    PATCHED_LEAF_ONLY,
    HARDENED_STANDALONE_UNTRUSTED,
    MISCONFIGURED_ALWAYS_TRUSTED,
    NON_LXD_SERVER,
    CLOSE_AFTER_PROBE_ONE
  }

  @Before
  public void setUp() {
    detector = new LxdMtlsAuthBypassDetector(fakeUtcClock, 3000);
    executor = Executors.newCachedThreadPool();
  }

  @After
  public void tearDown() throws IOException {
    if (serverSocket != null && !serverSocket.isClosed()) {
      serverSocket.close();
    }
    if (executor != null) {
      executor.shutdownNow();
    }
  }

  @Test
  public void detect_whenVulnerableLxdClusterAcceptsAppendedServerCert_reportsVulnerability()
      throws Exception {
    AtomicInteger probeCount = new AtomicInteger();
    int port = startFakeLxdServer(ServerMode.VULNERABLE_CHAIN_LOOP, probeCount);
    NetworkService service = createService(port, "https-alt");
    TargetInfo targetInfo =
        TargetInfo.newBuilder().addNetworkEndpoints(service.getNetworkEndpoint()).build();

    DetectionReportList reports = detector.detect(targetInfo, ImmutableList.of(service));

    assertThat(probeCount.get()).isEqualTo(2);
    assertThat(reports.getDetectionReportsList()).hasSize(1);
    DetectionReport report = reports.getDetectionReports(0);
    assertThat(report.getDetectionStatus()).isEqualTo(DetectionStatus.VULNERABILITY_VERIFIED);
    assertThat(report.getVulnerability().getSeverity()).isEqualTo(Severity.CRITICAL);
    assertThat(report.getVulnerability().getMainId())
        .isEqualTo(
            VulnerabilityId.newBuilder()
                .setPublisher("GOOGLE")
                .setValue("LXD_INCUS_MTLS_CERT_CHAIN_AUTH_BYPASS")
                .build());
    assertThat(report.getVulnerability().getRelatedIdList())
        .containsExactly(
            VulnerabilityId.newBuilder().setPublisher("CVE").setValue("CVE-2026-112816").build());
  }

  @Test
  public void detect_whenServiceLabeledTcpwrapped_reportsVulnerability() throws Exception {
    AtomicInteger probeCount = new AtomicInteger();
    int port = startFakeLxdServer(ServerMode.VULNERABLE_CHAIN_LOOP, probeCount);
    NetworkService service = createService(port, "tcpwrapped");
    TargetInfo targetInfo =
        TargetInfo.newBuilder().addNetworkEndpoints(service.getNetworkEndpoint()).build();

    DetectionReportList reports = detector.detect(targetInfo, ImmutableList.of(service));

    assertThat(probeCount.get()).isEqualTo(2);
    assertThat(reports.getDetectionReportsList()).hasSize(1);
  }

  @Test
  public void detect_whenPatchedIncusChecksOnlyLeafCertificate_returnsEmpty() throws Exception {
    AtomicInteger probeCount = new AtomicInteger();
    int port = startFakeLxdServer(ServerMode.PATCHED_LEAF_ONLY, probeCount);
    NetworkService service = createService(port, "https");
    TargetInfo targetInfo =
        TargetInfo.newBuilder().addNetworkEndpoints(service.getNetworkEndpoint()).build();

    DetectionReportList reports = detector.detect(targetInfo, ImmutableList.of(service));

    assertThat(probeCount.get()).isEqualTo(2);
    assertThat(reports.getDetectionReportsList()).isEmpty();
  }

  @Test
  public void detect_whenHardenedStandaloneServerCertNotInTrustStore_returnsEmpty()
      throws Exception {
    AtomicInteger probeCount = new AtomicInteger();
    int port = startFakeLxdServer(ServerMode.HARDENED_STANDALONE_UNTRUSTED, probeCount);
    NetworkService service = createService(port, "https");
    TargetInfo targetInfo =
        TargetInfo.newBuilder().addNetworkEndpoints(service.getNetworkEndpoint()).build();

    DetectionReportList reports = detector.detect(targetInfo, ImmutableList.of(service));

    assertThat(probeCount.get()).isEqualTo(2);
    assertThat(reports.getDetectionReportsList()).isEmpty();
  }

  @Test
  public void detect_whenMisconfiguredAlwaysTrustedServer_rejectedByNegativeControl()
      throws Exception {
    AtomicInteger probeCount = new AtomicInteger();
    int port = startFakeLxdServer(ServerMode.MISCONFIGURED_ALWAYS_TRUSTED, probeCount);
    NetworkService service = createService(port, "https");
    TargetInfo targetInfo =
        TargetInfo.newBuilder().addNetworkEndpoints(service.getNetworkEndpoint()).build();

    DetectionReportList reports = detector.detect(targetInfo, ImmutableList.of(service));

    assertThat(probeCount.get()).isEqualTo(1);
    assertThat(reports.getDetectionReportsList()).isEmpty();
  }

  @Test
  public void detect_whenNonLxdHttpsServer_shortCircuitsAfterProbeOne() throws Exception {
    AtomicInteger probeCount = new AtomicInteger();
    int port = startFakeLxdServer(ServerMode.NON_LXD_SERVER, probeCount);
    NetworkService service = createService(port, "https");
    TargetInfo targetInfo =
        TargetInfo.newBuilder().addNetworkEndpoints(service.getNetworkEndpoint()).build();

    DetectionReportList reports = detector.detect(targetInfo, ImmutableList.of(service));

    assertThat(probeCount.get()).isEqualTo(1);
    assertThat(reports.getDetectionReportsList()).isEmpty();
  }

  private int startFakeLxdServer(ServerMode mode, AtomicInteger probeCount) throws Exception {
    EphemeralIdentity serverIdentity = LxdMtlsAuthBypassDetector.generateEphemeralIdentity();
    byte[] serverCertEncoded = serverIdentity.certificate.getEncoded();

    SSLContext sslContext = SSLContext.getInstance("TLS");
    sslContext.init(
        new KeyManager[] {
          new X509ExtendedKeyManager() {
            @Override
            public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
              return "server";
            }

            @Override
            public String chooseEngineServerAlias(
                String keyType, Principal[] issuers, SSLEngine engine) {
              return "server";
            }

            @Override
            public X509Certificate[] getCertificateChain(String alias) {
              return new X509Certificate[] {serverIdentity.certificate};
            }

            @Override
            public PrivateKey getPrivateKey(String alias) {
              return serverIdentity.privateKey;
            }

            @Override
            public String[] getClientAliases(String keyType, Principal[] issuers) {
              return new String[0];
            }

            @Override
            public @Nullable String chooseClientAlias(
                String[] keyType, Principal[] issuers, Socket socket) {
              return null;
            }

            @Override
            public String[] getServerAliases(String keyType, Principal[] issuers) {
              return new String[] {"server"};
            }
          }
        },
        new TrustManager[] {
          new X509TrustManager() {
            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType) {}

            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType) {}

            @Override
            public X509Certificate[] getAcceptedIssuers() {
              return new X509Certificate[0];
            }
          }
        },
        new SecureRandom());

    serverSocket =
        (SSLServerSocket)
            sslContext
                .getServerSocketFactory()
                .createServerSocket(0, 16, InetAddress.getLoopbackAddress());
    serverSocket.setWantClientAuth(true);

    executor.execute(
        () -> {
          while (!serverSocket.isClosed()) {
            try (SSLSocket client = (SSLSocket) serverSocket.accept()) {
              client.startHandshake();
              probeCount.incrementAndGet();

              BufferedReader reader =
                  new BufferedReader(new InputStreamReader(client.getInputStream(), UTF_8));
              String line;
              while ((line = reader.readLine()) != null && !line.isEmpty()) {}

              String body;
              if (mode == ServerMode.NON_LXD_SERVER) {
                body = "{\"hello\":\"world\"}";
              } else {
                boolean trusted = evaluateClientChain(client, mode, serverCertEncoded);
                String auth = trusted ? "trusted" : "untrusted";
                body =
                    "{\"type\":\"sync\",\"status\":\"Success\",\"status_code\":200,"
                        + "\"metadata\":{\"api_version\":\"1.0\",\"auth\":\""
                        + auth
                        + "\"}}";
              }

              String resp =
                  "HTTP/1.0 200 OK\r\n"
                      + "Content-Type: application/json\r\n"
                      + "Content-Length: "
                      + body.length()
                      + "\r\n\r\n"
                      + body;
              OutputStream out = client.getOutputStream();
              out.write(resp.getBytes(UTF_8));
              out.flush();
              if (mode == ServerMode.CLOSE_AFTER_PROBE_ONE) {
                serverSocket.close();
              }
            } catch (Exception e) {
              // Ignore closed socket on teardown.
            }
          }
        });

    return serverSocket.getLocalPort();
  }

  private static boolean evaluateClientChain(
      SSLSocket client, ServerMode mode, byte[] serverCertEncoded) {
    Certificate[] peerCerts;
    try {
      peerCerts = client.getSession().getPeerCertificates();
    } catch (SSLPeerUnverifiedException e) {
      peerCerts = new Certificate[0];
    }

    return switch (mode) {
      case VULNERABLE_CHAIN_LOOP -> {
        for (Certificate cert : peerCerts) {
          try {
            if (Arrays.equals(cert.getEncoded(), serverCertEncoded)) {
              yield true;
            }
          } catch (Exception e) {
            // Ignore encoding failure.
          }
        }
        yield false;
      }
      case PATCHED_LEAF_ONLY -> {
        if (peerCerts.length > 0) {
          try {
            yield Arrays.equals(peerCerts[0].getEncoded(), serverCertEncoded);
          } catch (Exception e) {
            yield false;
          }
        }
        yield false;
      }
      case MISCONFIGURED_ALWAYS_TRUSTED -> true;
      case HARDENED_STANDALONE_UNTRUSTED, NON_LXD_SERVER, CLOSE_AFTER_PROBE_ONE -> false;
    };
  }

  @Test
  public void isSupportedService_matchesDefaultLxdPort8443AndSupportedServices() {
    NetworkService port8443CustomService = createService(8443, "custom-daemon");
    NetworkService webService = createService(9443, "radan-http");
    NetworkService lxdService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                NetworkEndpointUtils.forIpAndPort(
                    InetAddress.getLoopbackAddress().getHostAddress(), 9443))
            .setTransportProtocol(TransportProtocol.TRANSPORT_PROTOCOL_UNSPECIFIED)
            .setServiceName("  LXD  ")
            .build();
    NetworkService sshService = createService(2222, "ssh");

    assertThat(LxdMtlsAuthBypassDetector.isSupportedService(port8443CustomService)).isTrue();
    assertThat(LxdMtlsAuthBypassDetector.isSupportedService(webService)).isTrue();
    assertThat(LxdMtlsAuthBypassDetector.isSupportedService(lxdService)).isTrue();
    assertThat(LxdMtlsAuthBypassDetector.isSupportedService(sshService)).isFalse();
  }

  @Test
  public void detect_whenClosedPortOrProbeTwoFails_returnsEmpty() throws Exception {
    LxdMtlsAuthBypassDetector defaultTimeoutDetector = new LxdMtlsAuthBypassDetector(fakeUtcClock);

    // Probe 2 connection failure (server closes listening socket right after Probe 1).
    AtomicInteger probeCount = new AtomicInteger();
    int port = startFakeLxdServer(ServerMode.CLOSE_AFTER_PROBE_ONE, probeCount);
    NetworkService service = createService(port, "https");
    TargetInfo targetInfo =
        TargetInfo.newBuilder().addNetworkEndpoints(service.getNetworkEndpoint()).build();
    assertThat(detector.detect(targetInfo, ImmutableList.of(service)).getDetectionReportsList())
        .isEmpty();

    // Probe 1 connection failure (socket is already closed).
    assertThat(
            defaultTimeoutDetector
                .detect(targetInfo, ImmutableList.of(service))
                .getDetectionReportsList())
        .isEmpty();
  }

  @Test
  public void parseLxdHttpResponse_handlesMalformedAndEdgeCaseResponses() throws Exception {
    EphemeralIdentity identity = LxdMtlsAuthBypassDetector.generateEphemeralIdentity();
    identity.certificate.verify(identity.certificate.getPublicKey());
    assertThat(identity.certificate.getSerialNumber().intValue()).isEqualTo(1);

    // Valid HTTP/1.0 and HTTP/1.1 200 responses.
    ProbeResult validHttp10 =
        LxdMtlsAuthBypassDetector.parseLxdHttpResponse(
            "HTTP/1.0 200 OK\r\n"
                + "Content-Type: application/json\r\n\r\n"
                + "{\"type\":\"sync\",\"status_code\":200,"
                + "\"metadata\":{\"api_version\":\"1.0\",\"auth\":\"untrusted\"}}",
            identity.certificate);
    assertThat(validHttp10.isValidLxdApi).isTrue();
    assertThat(validHttp10.authState).isEqualTo("untrusted");

    ProbeResult validHttp11 =
        LxdMtlsAuthBypassDetector.parseLxdHttpResponse(
            "HTTP/1.1 200 OK\r\n"
                + "Content-Type: application/json\r\n\r\n"
                + "{\"type\":\"sync\",\"status_code\":200,"
                + "\"metadata\":{\"api_version\":\"1.0\",\"auth\":\"trusted\"}}",
            identity.certificate);
    assertThat(validHttp11.isValidLxdApi).isTrue();
    assertThat(validHttp11.authState).isEqualTo("trusted");

    // Missing HTTP header delimiter (\r\n\r\n).
    ProbeResult noHeaderEnd =
        LxdMtlsAuthBypassDetector.parseLxdHttpResponse("HTTP/1.0 200 OK", identity.certificate);
    assertThat(noHeaderEnd.isValidLxdApi).isFalse();

    // Non-200 HTTP status.
    ProbeResult notFound =
        LxdMtlsAuthBypassDetector.parseLxdHttpResponse(
            "HTTP/1.1 404 Not Found\r\n\r\n{\"type\":\"error\"}", identity.certificate);
    assertThat(notFound.isValidLxdApi).isFalse();

    // Valid JSON non-object body (JSON array).
    ProbeResult jsonArrayBody =
        LxdMtlsAuthBypassDetector.parseLxdHttpResponse(
            "HTTP/1.1 200 OK\r\n\r\n[]", identity.certificate);
    assertThat(jsonArrayBody.isValidLxdApi).isFalse();

    // Malformed JSON body.
    ProbeResult invalidJson =
        LxdMtlsAuthBypassDetector.parseLxdHttpResponse(
            "HTTP/1.1 200 OK\r\n\r\n{invalid-json}", identity.certificate);
    assertThat(invalidJson.isValidLxdApi).isFalse();

    // Non-sync type.
    ProbeResult nonSyncType =
        LxdMtlsAuthBypassDetector.parseLxdHttpResponse(
            "HTTP/1.1 200 OK\r\n\r\n"
                + "{\"type\":\"async\",\"status_code\":200,"
                + "\"metadata\":{\"api_version\":\"1.0\",\"auth\":\"untrusted\"}}",
            identity.certificate);
    assertThat(nonSyncType.isValidLxdApi).isFalse();

    // Non-200 status_code, missing status_code, non-primitive status_code, non-int status_code.
    ProbeResult non200StatusCode =
        LxdMtlsAuthBypassDetector.parseLxdHttpResponse(
            "HTTP/1.1 200 OK\r\n\r\n"
                + "{\"type\":\"sync\",\"status_code\":403,"
                + "\"metadata\":{\"api_version\":\"1.0\",\"auth\":\"untrusted\"}}",
            identity.certificate);
    assertThat(non200StatusCode.isValidLxdApi).isFalse();

    ProbeResult missingStatusCode =
        LxdMtlsAuthBypassDetector.parseLxdHttpResponse(
            "HTTP/1.1 200 OK\r\n\r\n"
                + "{\"type\":\"sync\","
                + "\"metadata\":{\"api_version\":\"1.0\",\"auth\":\"untrusted\"}}",
            identity.certificate);
    assertThat(missingStatusCode.isValidLxdApi).isFalse();

    ProbeResult nonPrimitiveStatusCode =
        LxdMtlsAuthBypassDetector.parseLxdHttpResponse(
            "HTTP/1.1 200 OK\r\n\r\n"
                + "{\"type\":\"sync\",\"status_code\":{},"
                + "\"metadata\":{\"api_version\":\"1.0\",\"auth\":\"untrusted\"}}",
            identity.certificate);
    assertThat(nonPrimitiveStatusCode.isValidLxdApi).isFalse();

    ProbeResult nonIntStatus =
        LxdMtlsAuthBypassDetector.parseLxdHttpResponse(
            "HTTP/1.1 200 OK\r\n\r\n"
                + "{\"type\":\"sync\",\"status_code\":\"bad\","
                + "\"metadata\":{\"api_version\":\"1.0\",\"auth\":\"untrusted\"}}",
            identity.certificate);
    assertThat(nonIntStatus.isValidLxdApi).isFalse();

    // Missing metadata and non-object metadata.
    ProbeResult missingMeta =
        LxdMtlsAuthBypassDetector.parseLxdHttpResponse(
            "HTTP/1.1 200 OK\r\n\r\n{\"type\":\"sync\",\"status_code\":200}", identity.certificate);
    assertThat(missingMeta.isValidLxdApi).isFalse();

    ProbeResult nonObjectMeta =
        LxdMtlsAuthBypassDetector.parseLxdHttpResponse(
            "HTTP/1.1 200 OK\r\n\r\n{\"type\":\"sync\",\"status_code\":200,\"metadata\":\"str\"}",
            identity.certificate);
    assertThat(nonObjectMeta.isValidLxdApi).isFalse();

    // Wrong api_version, missing auth, non-primitive auth, empty auth.
    ProbeResult wrongApiVersion =
        LxdMtlsAuthBypassDetector.parseLxdHttpResponse(
            "HTTP/1.1 200 OK\r\n\r\n"
                + "{\"type\":\"sync\",\"status_code\":200,"
                + "\"metadata\":{\"api_version\":\"2.0\",\"auth\":\"untrusted\"}}",
            identity.certificate);
    assertThat(wrongApiVersion.isValidLxdApi).isFalse();

    ProbeResult missingAuth =
        LxdMtlsAuthBypassDetector.parseLxdHttpResponse(
            "HTTP/1.1 200 OK\r\n\r\n"
                + "{\"type\":\"sync\",\"status_code\":200,"
                + "\"metadata\":{\"api_version\":\"1.0\"}}",
            identity.certificate);
    assertThat(missingAuth.isValidLxdApi).isFalse();

    ProbeResult nonPrimitiveAuth =
        LxdMtlsAuthBypassDetector.parseLxdHttpResponse(
            "HTTP/1.1 200 OK\r\n\r\n"
                + "{\"type\":\"sync\",\"status_code\":200,"
                + "\"metadata\":{\"api_version\":\"1.0\",\"auth\":{}}}",
            identity.certificate);
    assertThat(nonPrimitiveAuth.isValidLxdApi).isFalse();

    ProbeResult emptyAuth =
        LxdMtlsAuthBypassDetector.parseLxdHttpResponse(
            "HTTP/1.1 200 OK\r\n\r\n"
                + "{\"type\":\"sync\",\"status_code\":200,"
                + "\"metadata\":{\"api_version\":\"1.0\",\"auth\":\"\"}}",
            identity.certificate);
    assertThat(emptyAuth.isValidLxdApi).isFalse();

    // KeyManager and TrustManager helper methods.
    FixedChainKeyManager km =
        new FixedChainKeyManager(new X509Certificate[] {identity.certificate}, identity.privateKey);
    assertThat(km.chooseEngineClientAlias(new String[] {"EC"}, null, null))
        .isEqualTo("tsunami-ephemeral-client");
    assertThat(km.getClientAliases("EC", null))
        .asList()
        .containsExactly("tsunami-ephemeral-client");
    assertThat(km.getServerAliases("EC", null)).isEmpty();
    assertThat(km.chooseServerAlias("EC", null, null)).isNull();
    assertThat(km.getCertificateChain("other")).isNull();
    assertThat(km.getPrivateKey("other")).isNull();

    PermissiveTrustManager tm = new PermissiveTrustManager();
    tm.checkClientTrusted(new X509Certificate[] {identity.certificate}, "EC");
    assertThat(tm.getAcceptedIssuers()).isEmpty();
  }

  @Test
  public void getAdvisories_returnsCve2026112816Advisory() {
    assertThat(detector.getAdvisories()).hasSize(1);
    assertThat(detector.getAdvisories().get(0).getMainId().getValue())
        .isEqualTo("LXD_INCUS_MTLS_CERT_CHAIN_AUTH_BYPASS");
  }

  @Test
  public void detect_whenUnsupportedTransportOrService_skipsProbing() throws Exception {
    AtomicInteger probeCount = new AtomicInteger();
    int port = startFakeLxdServer(ServerMode.VULNERABLE_CHAIN_LOOP, probeCount);
    NetworkService udpService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                NetworkEndpointUtils.forIpAndPort(
                    InetAddress.getLoopbackAddress().getHostAddress(), port))
            .setTransportProtocol(TransportProtocol.UDP)
            .setServiceName("https")
            .build();
    NetworkService sshService = createService(port, "ssh");
    TargetInfo targetInfo =
        TargetInfo.newBuilder().addNetworkEndpoints(sshService.getNetworkEndpoint()).build();

    DetectionReportList reports =
        detector.detect(targetInfo, ImmutableList.of(udpService, sshService));

    assertThat(probeCount.get()).isEqualTo(0);
    assertThat(reports.getDetectionReportsList()).isEmpty();
  }

  private static NetworkService createService(int port, String serviceName) {
    return NetworkService.newBuilder()
        .setNetworkEndpoint(
            NetworkEndpointUtils.forIpAndPort(
                InetAddress.getLoopbackAddress().getHostAddress(), port))
        .setTransportProtocol(TransportProtocol.TCP)
        .setServiceName(serviceName)
        .build();
  }
}
