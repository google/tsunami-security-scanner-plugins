package com.google.tsunami.plugins.detectors.cves.cve202421181.weblogic.requests;

import com.google.tsunami.plugins.detectors.cves.cve202421181.giop.Giop10Request;
import com.google.tsunami.plugins.detectors.cves.cve202421181.giop.GiopPacket;
import com.google.tsunami.plugins.detectors.cves.cve202421181.giop.GiopPacketPayload;
import com.google.tsunami.plugins.detectors.cves.cve202421181.giop.GiopRequest;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

public class InitRequest extends GiopPacket {
  /*
  Generic IIOP 1.0 request, does not follow the format of the other requests
   */

  private final int requestId;

  public InitRequest(int requestId) {
    this.requestId = requestId;
  }

  @Override
  public Version version() {
    return Version.VERSION_1_0;
  }

  @Override
  public Type type() {
    return Type.GIOP_REQUEST;
  }

  @Override
  public boolean isLittleEndian() {
    return false;
  }

  @Override
  public boolean ziopEnabled() {
    return false;
  }

  @Override
  public boolean ziopSupported() {
    return false;
  }

  @Override
  public boolean isFragment() {
    return false;
  }

  @Override
  public GiopPacketPayload payload() {
    // Prepare Stub Data
    String stubDataString = "NameService";
    // size = 4 (size) + len(str) + 1 (null byte)
    ByteBuffer stubData = ByteBuffer.allocate(stubDataString.length() + 1 + 4);
    stubData.putInt(stubDataString.length() + 1);
    stubData.put(stubDataString.getBytes(StandardCharsets.UTF_8));
    stubData.put((byte) 0x00);

    // Send init request
    return Giop10Request.builder()
        .setRequestId(requestId)
        .setOperation(GiopRequest.Operation.OP_GET)
        .setObjectKey(Giop10Request.ObjectKey.KEY_INIT)
        .setStubData(stubData.array())
        .build();
  }
}
