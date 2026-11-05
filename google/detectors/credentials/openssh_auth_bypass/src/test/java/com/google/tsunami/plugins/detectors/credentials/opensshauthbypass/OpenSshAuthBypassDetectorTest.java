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
package com.google.tsunami.plugins.detectors.credentials.opensshauthbypass;

import static com.google.common.truth.Truth.assertThat;
import static com.google.common.truth.extensions.proto.ProtoTruth.assertThat;

import com.google.common.collect.ImmutableList;
import com.google.inject.AbstractModule;
import com.google.inject.Guice;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkEndpointUtils;
import com.google.tsunami.common.net.socket.TsunamiSocketFactory;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.common.time.testing.FakeUtcClockModule;
import com.google.tsunami.proto.AdditionalDetail;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.Software;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.TextData;
import com.google.tsunami.proto.TransportProtocol;
import com.google.tsunami.proto.Vulnerability;
import com.google.tsunami.proto.VulnerabilityId;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicInteger;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.inject.Inject;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;

/** Unit tests for {@link OpenSshAuthBypassDetector}. */
@RunWith(JUnit4.class)
public final class OpenSshAuthBypassDetectorTest {

  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2026-11-05T00:00:00.00Z"));

  private final TsunamiSocketFactory socketFactoryMock = Mockito.mock(TsunamiSocketFactory.class);

  @Inject private OpenSshAuthBypassDetector detector;

  private FakeSshServer fakeSshServer;

  @Before
  public void setUp() throws Exception {
    fakeSshServer = new FakeSshServer();
    fakeSshServer.start();

    Mockito.when(
            socketFactoryMock.createSocket(ArgumentMatchers.anyString(), ArgumentMatchers.anyInt()))
        .thenAnswer(
            inv -> new Socket(InetAddress.getLoopbackAddress(), fakeSshServer.getPort()));

    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new OpenSshAuthBypassDetectorBootstrapModule(),
            new AbstractModule() {
              @Override
              protected void configure() {
                bind(TsunamiSocketFactory.class).toInstance(socketFactoryMock);
              }
            })
        .injectMembers(this);
  }

  @After
  public void tearDown() throws Exception {
    if (fakeSshServer != null) {
      fakeSshServer.close();
    }
  }

  @Test
  public void getAdvisories_always_includesCve2026123158RelatedId() {
    assertThat(detector.getAdvisories())
        .containsExactly(
            Vulnerability.newBuilder()
                .setMainId(
                    VulnerabilityId.newBuilder()
                        .setPublisher("GOOGLE")
                        .setValue("OPENSSH_MUSL_PASSWORD_AUTH_BYPASS"))
                .addRelatedId(
                    VulnerabilityId.newBuilder().setPublisher("CVE").setValue("CVE-2026-123158"))
                .setSeverity(Severity.CRITICAL)
                .setTitle(OpenSshAuthBypassDetector.VULNERABILITY_REPORT_TITLE)
                .setDescription(OpenSshAuthBypassDetector.VULN_DESCRIPTION)
                .setRecommendation(OpenSshAuthBypassDetector.RECOMMENDATION)
                .build());
  }

  @Test
  public void detect_whenVulnerableOnSecondPromptInSameSession_returnsVulnerability() {
    // Models real OpenSSH + musl /etc/shadow behavior (e.g., OpenSSH 8.8p1 on Alpine, 10.6p1 on
    // OpenWrt): prompt #1 (index 0) caches pick_salt() and wipes musl's static getspnam() buffer
    // (failing), while prompt #2 (index 1) in the same SSH connection reuses the cached salt and
    // succeeds.
    fakeSshServer.setAuthPolicy(
        (user, pw, promptIndex) -> promptIndex >= 1 && user.equals("root") && pw.length() > 256);
    NetworkService service = createSshService(fakeSshServer.getPort());
    TargetInfo targetInfo = TargetInfo.getDefaultInstance();

    DetectionReportList reports = detector.detect(targetInfo, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList())
        .containsExactly(buildExpectedReport(targetInfo, service, "root"));
    assertThat(fakeSshServer.getConnectionCount()).isEqualTo(3);
    assertThat(fakeSshServer.getAuthRequestCount()).isEqualTo(6);
  }

  @Test
  public void detect_whenVulnerableOnFirstPrompt_returnsVulnerability() {
    fakeSshServer.setAuthPolicy(
        (user, pw, promptIndex) -> user.equals("root") && pw.length() > 256);
    NetworkService service = createSshService(fakeSshServer.getPort());
    TargetInfo targetInfo = TargetInfo.getDefaultInstance();

    DetectionReportList reports = detector.detect(targetInfo, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList())
        .containsExactly(buildExpectedReport(targetInfo, service, "root"));
    assertThat(fakeSshServer.getConnectionCount()).isEqualTo(3);
  }

  @Test
  public void detect_whenRootNotPermittedButSshuserVulnerable_returnsVulnerability() {
    fakeSshServer.setAuthPolicy(
        (user, pw, promptIndex) -> promptIndex >= 1 && user.equals("sshuser") && pw.length() > 256);
    NetworkService service = createSshService(fakeSshServer.getPort());
    TargetInfo targetInfo = TargetInfo.getDefaultInstance();

    DetectionReportList reports = detector.detect(targetInfo, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList())
        .containsExactly(buildExpectedReport(targetInfo, service, "sshuser"));
    assertThat(fakeSshServer.getConnectionCount()).isEqualTo(5);
  }

  @Test
  public void detect_whenOnlyFirstLongPasswordAccepted_returnsEmpty() {
    fakeSshServer.setAuthPolicy(
        (user, pw, promptIndex) ->
            user.equals("root") && pw.equals(SshPasswordAuthClient.LONG_BYPASS_PASSWORD));
    NetworkService service = createSshService(fakeSshServer.getPort());
    TargetInfo targetInfo = TargetInfo.getDefaultInstance();

    DetectionReportList reports = detector.detect(targetInfo, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList()).isEmpty();
  }

  @Test
  public void detect_whenPatchedServerRejectsLongPasswords_returnsEmpty() {
    fakeSshServer.setAuthPolicy((user, pw, promptIndex) -> false);
    NetworkService service = createSshService(fakeSshServer.getPort());
    TargetInfo targetInfo = TargetInfo.getDefaultInstance();

    DetectionReportList reports = detector.detect(targetInfo, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList()).isEmpty();
  }

  @Test
  public void detect_whenPasswordAuthenticationDisabled_stopsEarlyAndReturnsEmpty() {
    fakeSshServer.setAllowedAuthMethods("publickey,keyboard-interactive");
    fakeSshServer.setAuthPolicy((user, pw, promptIndex) -> false);
    NetworkService service = createSshService(fakeSshServer.getPort());
    TargetInfo targetInfo = TargetInfo.getDefaultInstance();

    DetectionReportList reports = detector.detect(targetInfo, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(fakeSshServer.getConnectionCount()).isEqualTo(1);
    assertThat(fakeSshServer.getAuthRequestCount()).isEqualTo(1);
  }

  @Test
  public void detect_whenServerAcceptsShortInvalidPassword_returnsEmpty() {
    fakeSshServer.setAuthPolicy((user, pw, promptIndex) -> true);
    NetworkService service = createSshService(fakeSshServer.getPort());
    TargetInfo targetInfo = TargetInfo.getDefaultInstance();

    DetectionReportList reports = detector.detect(targetInfo, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList()).isEmpty();
  }

  @Test
  public void detect_whenTargetIsNotOpenSsh_returnsEmpty() {
    fakeSshServer.setServerBanner("SSH-2.0-Dropbear_2024.85");
    fakeSshServer.setAuthPolicy((user, pw, promptIndex) -> pw.length() > 256);
    NetworkService service = createSshService(fakeSshServer.getPort());
    TargetInfo targetInfo = TargetInfo.getDefaultInstance();

    DetectionReportList reports = detector.detect(targetInfo, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(fakeSshServer.getConnectionCount()).isEqualTo(1);
  }

  @Test
  public void detect_whenTcpwrappedOnPort22AndVulnerable_returnsVulnerability() {
    fakeSshServer.setAuthPolicy(
        (user, pw, promptIndex) -> promptIndex >= 1 && user.equals("root") && pw.length() > 256);
    NetworkService service =
        NetworkService.newBuilder()
            .setNetworkEndpoint(NetworkEndpointUtils.forIpAndPort("127.0.0.1", 22))
            .setTransportProtocol(TransportProtocol.TCP)
            .setServiceName("tcpwrapped")
            .build();
    TargetInfo targetInfo = TargetInfo.getDefaultInstance();

    DetectionReportList reports = detector.detect(targetInfo, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList())
        .containsExactly(buildExpectedReport(targetInfo, service, "root"));
    assertThat(fakeSshServer.getConnectionCount()).isEqualTo(3);
  }

  @Test
  public void detect_whenTcpwrappedOnNon22Port_skipsServiceAndReturnsEmpty() {
    fakeSshServer.setAuthPolicy(
        (user, pw, promptIndex) -> user.equals("root") && pw.length() > 256);
    NetworkService service =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                NetworkEndpointUtils.forIpAndPort("127.0.0.1", fakeSshServer.getPort()))
            .setTransportProtocol(TransportProtocol.TCP)
            .setServiceName("tcpwrapped")
            .build();
    TargetInfo targetInfo = TargetInfo.getDefaultInstance();

    DetectionReportList reports = detector.detect(targetInfo, ImmutableList.of(service));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    assertThat(fakeSshServer.getConnectionCount()).isEqualTo(0);
  }

  private static NetworkService createSshService(int port) {
    return NetworkService.newBuilder()
        .setNetworkEndpoint(NetworkEndpointUtils.forIpAndPort("127.0.0.1", port))
        .setTransportProtocol(TransportProtocol.TCP)
        .setSoftware(Software.newBuilder().setName("OpenSSH"))
        .setServiceName("ssh")
        .build();
  }

  private DetectionReport buildExpectedReport(
      TargetInfo targetInfo, NetworkService service, String username) {
    AdditionalDetail detail =
        AdditionalDetail.newBuilder()
            .setDescription(
                "Authentication bypass verified for locked account using >256-byte password")
            .setTextData(
                TextData.newBuilder()
                    .setText(
                        String.format(
                            "Successfully authenticated as \"%s\" with distinct %d-byte passwords"
                                + " while rejecting <=256-byte passwords.",
                            username, SshPasswordAuthClient.LONG_BYPASS_PASSWORD.length())))
            .build();
    return DetectionReport.newBuilder()
        .setTargetInfo(targetInfo)
        .setNetworkService(service)
        .setDetectionTimestamp(Timestamps.fromMillis(Instant.now(fakeUtcClock).toEpochMilli()))
        .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
        .setVulnerability(
            Vulnerability.newBuilder()
                .setMainId(
                    VulnerabilityId.newBuilder()
                        .setPublisher("GOOGLE")
                        .setValue("OPENSSH_MUSL_PASSWORD_AUTH_BYPASS"))
                .addRelatedId(
                    VulnerabilityId.newBuilder().setPublisher("CVE").setValue("CVE-2026-123158"))
                .setSeverity(Severity.CRITICAL)
                .setTitle(OpenSshAuthBypassDetector.VULNERABILITY_REPORT_TITLE)
                .setDescription(OpenSshAuthBypassDetector.VULN_DESCRIPTION)
                .setRecommendation(OpenSshAuthBypassDetector.RECOMMENDATION)
                .addAdditionalDetails(detail)
                .build())
        .build();
  }

  @FunctionalInterface
  private interface AuthPolicy {
    boolean authenticate(String username, String password, int promptIndexInConnection);
  }

  /** Minimal loopback SSH-2.0 server for testing {@link OpenSshAuthBypassDetector}. */
  private static final class FakeSshServer implements AutoCloseable {
    private final ServerSocket serverSocket;
    private final AtomicInteger connectionCount = new AtomicInteger(0);
    private final AtomicInteger authRequestCount = new AtomicInteger(0);
    private volatile String serverBanner = "SSH-2.0-OpenSSH_9.9";
    private volatile String allowedAuthMethods = "publickey,password,keyboard-interactive";
    private volatile AuthPolicy authPolicy = (u, p, i) -> false;
    private volatile boolean running = true;
    private Thread acceptThread;

    FakeSshServer() throws IOException {
      this.serverSocket = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
    }

    int getPort() {
      return serverSocket.getLocalPort();
    }

    int getConnectionCount() {
      return connectionCount.get();
    }

    int getAuthRequestCount() {
      return authRequestCount.get();
    }

    void setServerBanner(String banner) {
      this.serverBanner = banner;
    }

    void setAllowedAuthMethods(String methods) {
      this.allowedAuthMethods = methods;
    }

    void setAuthPolicy(AuthPolicy policy) {
      this.authPolicy = policy;
    }

    void start() {
      acceptThread =
          new Thread(
              () -> {
                while (running) {
                  try {
                    Socket client = serverSocket.accept();
                    connectionCount.incrementAndGet();
                    handleClient(client);
                  } catch (IOException e) {
                    if (!running) {
                      break;
                    }
                  }
                }
              });
      acceptThread.setDaemon(true);
      acceptThread.start();
    }

    private void handleClient(Socket socket) {
      try (Socket s = socket) {
        s.setSoTimeout(5000);
        InputStream in = s.getInputStream();
        OutputStream out = s.getOutputStream();

        String banner = serverBanner;
        out.write((banner + "\r\n").getBytes(StandardCharsets.US_ASCII));
        out.flush();

        // Read client version line.
        ByteArrayOutputStream clientBannerBuf = new ByteArrayOutputStream();
        while (true) {
          int b = in.read();
          if (b == -1 || b == '\n') {
            break;
          }
          if (b != '\r') {
            clientBannerBuf.write(b);
          }
        }
        String clientBanner = clientBannerBuf.toString(StandardCharsets.US_ASCII);
        if (!banner.startsWith("SSH-2.0-OpenSSH")) {
          return;
        }

        int serverSeqNo = 0;
        int clientSeqNo = 0;

        byte[] ic = readPlainPacket(in);
        clientSeqNo++;

        ByteArrayOutputStream kexInit = new ByteArrayOutputStream();
        kexInit.write(SshPasswordAuthClient.SSH_MSG_KEXINIT);
        kexInit.write(new byte[16]);
        SshPasswordAuthClient.writeNameList(kexInit, "ecdh-sha2-nistp256");
        SshPasswordAuthClient.writeNameList(kexInit, "ssh-ed25519");
        SshPasswordAuthClient.writeNameList(kexInit, "aes128-ctr");
        SshPasswordAuthClient.writeNameList(kexInit, "aes128-ctr");
        SshPasswordAuthClient.writeNameList(kexInit, "hmac-sha2-256");
        SshPasswordAuthClient.writeNameList(kexInit, "hmac-sha2-256");
        SshPasswordAuthClient.writeNameList(kexInit, "none");
        SshPasswordAuthClient.writeNameList(kexInit, "none");
        SshPasswordAuthClient.writeNameList(kexInit, "");
        SshPasswordAuthClient.writeNameList(kexInit, "");
        kexInit.write(0);
        SshPasswordAuthClient.writeUint32(kexInit, 0);
        byte[] is = kexInit.toByteArray();
        sendPlainPacket(out, is);
        serverSeqNo++;

        byte[] ecdhInit = readPlainPacket(in);
        clientSeqNo++;
        ByteBuffer initBuf = ByteBuffer.wrap(ecdhInit, 1, ecdhInit.length - 1);
        byte[] qc = SshPasswordAuthClient.readSshString(initBuf);

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"), new SecureRandom());
        KeyPair serverKp = kpg.generateKeyPair();
        ECPublicKey serverPub = (ECPublicKey) serverKp.getPublic();
        byte[] qs = SshPasswordAuthClient.encodeUncompressedEcPoint(serverPub.getW());

        ECPublicKey clientPub = SshPasswordAuthClient.decodeUncompressedEcPoint(qc, serverPub);
        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(serverKp.getPrivate());
        ka.doPhase(clientPub, true);
        byte[] mpintK = SshPasswordAuthClient.encodeMpintUnsigned(ka.generateSecret());

        byte[] ks = "fake-host-key".getBytes(StandardCharsets.US_ASCII);
        byte[] exchangeHash =
            SshPasswordAuthClient.computeExchangeHash(
                clientBanner.getBytes(StandardCharsets.US_ASCII),
                banner.getBytes(StandardCharsets.US_ASCII),
                ic,
                is,
                ks,
                qc,
                qs,
                mpintK);

        ByteArrayOutputStream ecdhReply = new ByteArrayOutputStream();
        ecdhReply.write(SshPasswordAuthClient.SSH_MSG_KEX_ECDH_REPLY);
        SshPasswordAuthClient.writeSshString(ecdhReply, ks);
        SshPasswordAuthClient.writeSshString(ecdhReply, qs);
        SshPasswordAuthClient.writeSshString(
            ecdhReply, "fake-sig".getBytes(StandardCharsets.US_ASCII));
        sendPlainPacket(out, ecdhReply.toByteArray());
        serverSeqNo++;

        byte[] unusedNewKeys = readPlainPacket(in); // Client SSH_MSG_NEWKEYS
        if (unusedNewKeys.length == 0) {
          return;
        }
        clientSeqNo++;
        sendPlainPacket(out, new byte[] {SshPasswordAuthClient.SSH_MSG_NEWKEYS});
        serverSeqNo++;

        byte[] ivC2S = SshPasswordAuthClient.deriveKey(mpintK, exchangeHash, 'A', 16);
        byte[] ivS2C = SshPasswordAuthClient.deriveKey(mpintK, exchangeHash, 'B', 16);
        byte[] keyC2S = SshPasswordAuthClient.deriveKey(mpintK, exchangeHash, 'C', 16);
        byte[] keyS2C = SshPasswordAuthClient.deriveKey(mpintK, exchangeHash, 'D', 16);
        byte[] macKeyC2S = SshPasswordAuthClient.deriveKey(mpintK, exchangeHash, 'E', 32);
        byte[] macKeyS2C = SshPasswordAuthClient.deriveKey(mpintK, exchangeHash, 'F', 32);

        Cipher decC2S = Cipher.getInstance("AES/CTR/NoPadding");
        decC2S.init(
            Cipher.DECRYPT_MODE, new SecretKeySpec(keyC2S, "AES"), new IvParameterSpec(ivC2S));
        Cipher encS2C = Cipher.getInstance("AES/CTR/NoPadding");
        encS2C.init(
            Cipher.ENCRYPT_MODE, new SecretKeySpec(keyS2C, "AES"), new IvParameterSpec(ivS2C));
        Mac macC2S = Mac.getInstance("HmacSHA256");
        macC2S.init(new SecretKeySpec(macKeyC2S, "HmacSHA256"));
        Mac macS2C = Mac.getInstance("HmacSHA256");
        macS2C.init(new SecretKeySpec(macKeyS2C, "HmacSHA256"));

        // Read SSH_MSG_SERVICE_REQUEST
        byte[] serviceReq = readEncryptedPacket(in, decC2S, macC2S, clientSeqNo++);
        if (serviceReq[0] != SshPasswordAuthClient.SSH_MSG_SERVICE_REQUEST) {
          return;
        }
        ByteArrayOutputStream serviceAccept = new ByteArrayOutputStream();
        serviceAccept.write(SshPasswordAuthClient.SSH_MSG_SERVICE_ACCEPT);
        SshPasswordAuthClient.writeSshString(
            serviceAccept, "ssh-userauth".getBytes(StandardCharsets.US_ASCII));
        sendEncryptedPacket(out, serviceAccept.toByteArray(), encS2C, macS2C, serverSeqNo++);

        // Handle SSH_MSG_USERAUTH_REQUEST loop
        int promptIndex = 0;
        while (true) {
          byte[] req = readEncryptedPacket(in, decC2S, macC2S, clientSeqNo++);
          if (req.length == 0 || req[0] == SshPasswordAuthClient.SSH_MSG_DISCONNECT) {
            break;
          }
          if (req[0] != SshPasswordAuthClient.SSH_MSG_USERAUTH_REQUEST) {
            break;
          }
          authRequestCount.incrementAndGet();
          ByteBuffer buf = ByteBuffer.wrap(req, 1, req.length - 1);
          String user =
              new String(SshPasswordAuthClient.readSshString(buf), StandardCharsets.UTF_8);
          byte[] serviceBytes = SshPasswordAuthClient.readSshString(buf); // service
          if (serviceBytes.length == 0) {
            break;
          }
          String method =
              new String(SshPasswordAuthClient.readSshString(buf), StandardCharsets.US_ASCII);
          buf.get(); // boolean false
          String password =
              new String(SshPasswordAuthClient.readSshString(buf), StandardCharsets.UTF_8);

          boolean accepted =
              "password".equals(method)
                  && allowedAuthMethods.contains("password")
                  && authPolicy.authenticate(user, password, promptIndex);
          promptIndex++;

          if (accepted) {
            sendEncryptedPacket(
                out,
                new byte[] {SshPasswordAuthClient.SSH_MSG_USERAUTH_SUCCESS},
                encS2C,
                macS2C,
                serverSeqNo++);
          } else {
            ByteArrayOutputStream fail = new ByteArrayOutputStream();
            fail.write(SshPasswordAuthClient.SSH_MSG_USERAUTH_FAILURE);
            SshPasswordAuthClient.writeNameList(fail, allowedAuthMethods);
            fail.write(0); // partial success = false
            sendEncryptedPacket(out, fail.toByteArray(), encS2C, macS2C, serverSeqNo++);
          }
        }
      } catch (Exception ignored) {
        // Connection closed by client.
      }
    }

    private static void sendPlainPacket(OutputStream out, byte[] payload) throws IOException {
      int paddingLen = 8 - ((4 + 1 + payload.length) % 8);
      if (paddingLen < 4) {
        paddingLen += 8;
      }
      int packetLen = 1 + payload.length + paddingLen;
      ByteBuffer buf = ByteBuffer.allocate(4 + packetLen).order(ByteOrder.BIG_ENDIAN);
      buf.putInt(packetLen);
      buf.put((byte) paddingLen);
      buf.put(payload);
      buf.put(new byte[paddingLen]);
      out.write(buf.array());
      out.flush();
    }

    private static byte[] readPlainPacket(InputStream in) throws IOException {
      byte[] header = new byte[4];
      SshPasswordAuthClient.readFully(in, header, 0, 4);
      int packetLen = ByteBuffer.wrap(header).order(ByteOrder.BIG_ENDIAN).getInt();
      byte[] body = new byte[packetLen];
      SshPasswordAuthClient.readFully(in, body, 0, packetLen);
      int paddingLen = body[0] & 0xFF;
      return Arrays.copyOfRange(body, 1, packetLen - paddingLen);
    }

    private static void sendEncryptedPacket(
        OutputStream out, byte[] payload, Cipher enc, Mac mac, int seqNo) throws IOException {
      int paddingLen = 16 - ((4 + 1 + payload.length) % 16);
      if (paddingLen < 4) {
        paddingLen += 16;
      }
      int packetLen = 1 + payload.length + paddingLen;
      ByteBuffer unenc = ByteBuffer.allocate(4 + packetLen).order(ByteOrder.BIG_ENDIAN);
      unenc.putInt(packetLen);
      unenc.put((byte) paddingLen);
      unenc.put(payload);
      unenc.put(new byte[paddingLen]);
      byte[] unencBytes = unenc.array();

      byte[] seqBytes = ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).putInt(seqNo).array();
      mac.update(seqBytes);
      mac.update(unencBytes);
      byte[] macBytes = mac.doFinal();
      out.write(enc.update(unencBytes));
      out.write(macBytes);
      out.flush();
    }

    private static byte[] readEncryptedPacket(InputStream in, Cipher dec, Mac mac, int seqNo)
        throws IOException {
      byte[] firstEnc = new byte[16];
      SshPasswordAuthClient.readFully(in, firstEnc, 0, 16);
      byte[] firstDec = dec.update(firstEnc);
      int packetLen = ByteBuffer.wrap(firstDec, 0, 4).order(ByteOrder.BIG_ENDIAN).getInt();
      int remLen = (4 + packetLen) - 16;
      byte[] fullDec = new byte[4 + packetLen];
      System.arraycopy(firstDec, 0, fullDec, 0, 16);
      if (remLen > 0) {
        byte[] remEnc = new byte[remLen];
        SshPasswordAuthClient.readFully(in, remEnc, 0, remLen);
        byte[] remDec = dec.update(remEnc);
        System.arraycopy(remDec, 0, fullDec, 16, remLen);
      }
      byte[] recvMac = new byte[32];
      SshPasswordAuthClient.readFully(in, recvMac, 0, 32);
      byte[] seqBytes = ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).putInt(seqNo).array();
      mac.update(seqBytes);
      mac.update(fullDec);
      if (!MessageDigest.isEqual(recvMac, mac.doFinal())) {
        throw new IOException("MAC mismatch");
      }
      int paddingLen = fullDec[4] & 0xFF;
      return Arrays.copyOfRange(fullDec, 5, 4 + packetLen - paddingLen);
    }

    @Override
    public void close() throws IOException {
      running = false;
      serverSocket.close();
    }
  }
}
