package com.google.tsunami.plugins.detectors.cves.cve202421181.weblogic;

import static com.google.common.base.Verify.verify;

import com.google.tsunami.plugins.detectors.cves.cve202421181.Utils;
import com.google.tsunami.plugins.detectors.cves.cve202421181.giop.Giop10Reply;
import com.google.tsunami.plugins.detectors.cves.cve202421181.giop.Giop12Reply;
import com.google.tsunami.plugins.detectors.cves.cve202421181.giop.GiopPacket;
import com.google.tsunami.plugins.detectors.cves.cve202421181.giop.GiopReply;
import com.google.tsunami.plugins.detectors.cves.cve202421181.giop.ServiceContext;
import com.google.tsunami.plugins.detectors.cves.cve202421181.weblogic.requests.InitRequestFactory;
import com.google.tsunami.plugins.detectors.cves.cve202421181.weblogic.requests.RebindRequestFactory;
import com.google.tsunami.plugins.detectors.cves.cve202421181.weblogic.requests.ResolveRequestFactory;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import javax.net.SocketFactory;

public class WeblogicClient {
  // Network
  String hostname;
  int port;
  Socket socket = null;
  BufferedOutputStream out;
  BufferedInputStream in;
  SocketFactory socketFactory;

  // Constants
  int CONNECT_TIMEOUT = 5000;
  int READ_TIMEOUT = 2000;
  int BUFFER_SIZE = 16384;
  int WEBLOGIC_VERSION_SERVICE_ID = 0x42454100;
  static final byte[] WEBLOGIC_KEY_ADDRESS_IDENTIFIER = Utils.hexStringToByteArray("0042454108");
  static final String T3_VERSION_CHECK = "t3 9.2.0.0\nAS:255\nHL:0\n\n";

  // WebLogic Server info
  private final int[] version = new int[4];
  private byte[] keyAddress;

  // Requests tracking
  private int requestId = 5;

  private WeblogicClient(String hostname, int port, SocketFactory socketFactory) {
    this.hostname = hostname;
    this.port = port;
    this.socketFactory = socketFactory;
  }

  private void connect() throws IOException {
    verify(socket == null || !socket.isConnected());
    this.socket = socketFactory.createSocket();
    this.socket.connect(new InetSocketAddress(hostname, port), CONNECT_TIMEOUT);
    this.socket.setSoTimeout(READ_TIMEOUT);

    // Get input and output streams
    this.out = new BufferedOutputStream(socket.getOutputStream());
    this.in = new BufferedInputStream(socket.getInputStream());
  }

  public void disconnect() throws IOException {
    this.socket.close();
    this.socket = null;
  }

  private ByteBuffer read() throws IOException {
    verify(socket != null && socket.isConnected());
    byte[] buffer = new byte[BUFFER_SIZE];
    int b = in.read(buffer, 0, buffer.length);
    if (b < 1) {
      throw new IOException("Unexpected end of stream");
    }
    return ByteBuffer.wrap(buffer);
  }

  private void write(byte[] buffer) throws IOException {
    verify(socket != null && socket.isConnected());
    out.write(buffer);
    out.flush();
  }

  public static String doT3VersionCheck(String hostname, int port, SocketFactory socketFactory)
      throws IOException {
    /*
    Example response:
    HELO:12.2.1.3.false
    AS:2048
    HL:19
    MS:10000000
    PN:DOMAIN
     */

    // Send probe
    byte[] response;
    WeblogicClient tempClient = new WeblogicClient(hostname, port, socketFactory);
    tempClient.connect();
    tempClient.write(T3_VERSION_CHECK.getBytes(StandardCharsets.UTF_8));
    response = tempClient.read().array();
    tempClient.disconnect();

    // Check 'HELO' magic
    if (response[0] != 'H' || response[1] != 'E' || response[2] != 'L' || response[3] != 'O') {
      throw new RuntimeException("Unexpected response from T3 version check");
    }

    // Parse version line
    String responseString = new String(response, StandardCharsets.UTF_8);
    String versionLine = responseString.split("\n", 2)[0].split(":")[1];

    String[] versionParts = versionLine.split("\\.");
    if (versionParts.length < 4) {
      throw new RuntimeException("Unexpected version number format: " + versionLine);
    }

    return String.format(
        "%s.%s.%s.%s", versionParts[0], versionParts[1], versionParts[2], versionParts[3]);
  }

  public static WeblogicClient initialize(String hostname, int port, SocketFactory socketFactory)
      throws IOException {
    WeblogicClient client = new WeblogicClient(hostname, port, socketFactory);
    client.connect();
    client.sendInitRequest();
    client.getInitResponse();
    return client;
  }

  private void sendRequest(GiopPacket packet) {
    byte[] bytesToSend = packet.serialize();
    try {
      this.write(bytesToSend);
    } catch (IOException e) {
      throw new RuntimeException("Failed to send request", e);
    }
    this.requestId += 1;
  }

  private GiopPacket receiveResponse() {
    // Receive response
    ByteBuffer replyBuffer;
    try {
      replyBuffer = read();
    } catch (IOException e) {
      throw new RuntimeException("Failed to receive rebind response", e);
    }

    GiopPacket reply;
    try {
      reply = GiopPacket.deserialize(replyBuffer);
    } catch (Exception e) {
      throw new RuntimeException("Failed to deserialize response:", e);
    }

    if (reply.type() != GiopPacket.Type.GIOP_REPLY) {
      throw new RuntimeException("Message is not a GIOP_REPLY");
    }

    GiopReply replyPayload = (GiopReply) reply.payload();
    if (replyPayload.requestId() != requestId - 1) {
      throw new RuntimeException("GIOP reply payload does not match sent request ID");
    }

    return reply;
  }

  private boolean isLocationForward(GiopPacket packet) {
    verify(packet.type() == GiopPacket.Type.GIOP_REPLY);
    if (packet.version() != GiopPacket.Version.VERSION_1_2) {
      return false;
    }

    Giop12Reply replyPayload = (Giop12Reply) packet.payload();
    if (replyPayload.replyStatus() != GiopReply.ReplyStatus.STATUS_LOCATION_FORWARD) {
      return false;
    }

    if (!replyPayload.iorReference().isPresent()) {
      throw new RuntimeException("GIOP Location Forward Reply does not contain IOR reference");
    }

    // The IOR Object Key contains the new address
    // Update the locally stored address
    this.keyAddress = replyPayload.iorReference().get().objectKey();
    return true;
  }

  // INIT REQUEST

  public void sendInitRequest() {
    GiopPacket packet = InitRequestFactory.generate(requestId);
    this.sendRequest(packet);
  }

  private static byte[] extractKeyAddress(byte[] data) {
    int offset = Utils.arrayIndexOf(data, WEBLOGIC_KEY_ADDRESS_IDENTIFIER);
    // Reading buffer
    ByteBuffer stubDataBuffer = ByteBuffer.wrap(data);

    // Read total length
    // int located 4 bytes before actual key address
    stubDataBuffer.position(offset - 4);
    int keyAddressLength = stubDataBuffer.getInt();

    byte[] keyAddress = new byte[keyAddressLength];
    stubDataBuffer.get(keyAddress, 0, keyAddressLength);
    return keyAddress;
  }

  private GiopPacket getInitResponse() {
    GiopPacket reply = receiveResponse();
    Giop10Reply replyPayload = (Giop10Reply) reply.payload();

    if (reply.version() != GiopPacket.Version.VERSION_1_0) {
      throw new RuntimeException("GIOP Reply has unexpected version");
    }

    try {
      // Detect WebLogic version
      boolean foundVersion = false;
      for (ServiceContext serviceContext : replyPayload.serviceContextList()) {
        if (serviceContext.serviceId() == WEBLOGIC_VERSION_SERVICE_ID) {
          byte[] contextData = serviceContext.contextData();
          for (int i = 0; i < contextData.length; i++) {
            this.version[i] = contextData[i];
          }
          foundVersion = true;
        }
      }
      if (!foundVersion) {
        throw new RuntimeException("Could not find WebLogic version in Init response");
      }

      // Extract WebLogic keyAddress from stub data
      this.keyAddress = WeblogicClient.extractKeyAddress(replyPayload.stubData());
    } catch (Exception e) {
      throw new RuntimeException("GIOP INIT Response Parsing Exception.", e);
    }
    return reply;
  }

  // REBIND
  public GiopPacket performRebind(String referenceName, byte[] payload) {
    GiopPacket reply;
    do {
      GiopPacket request =
          RebindRequestFactory.generate(this.requestId, this.keyAddress, referenceName, payload);
      this.sendRequest(request);
      reply = this.receiveResponse();
    } while (isLocationForward(reply));
    return reply;
  }

  // RESOLVE
  public GiopPacket performResolve(String referenceName) {
    GiopPacket reply;
    do {
      GiopPacket request =
          ResolveRequestFactory.generate(this.requestId, this.keyAddress, referenceName);
      this.sendRequest(request);
      reply = this.receiveResponse();
    } while (isLocationForward(reply));
    return reply;
  }

  public String getVersion() {
    return String.format("%d.%d.%d.%d", version[0], version[1], version[2], version[3]);
  }
}
