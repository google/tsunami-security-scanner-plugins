package com.google.tsunami.plugins.detectors.cves.cve202421181.weblogic.requests;

import com.google.tsunami.plugins.detectors.cves.cve202421181.giop.Giop10Request;
import com.google.tsunami.plugins.detectors.cves.cve202421181.giop.GiopPacket;
import com.google.tsunami.plugins.detectors.cves.cve202421181.giop.GiopPacketPayload;
import com.google.tsunami.plugins.detectors.cves.cve202421181.giop.GiopRequest;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

public class InitRequestFactory {
  /*
  Generic IIOP 1.0 request, does not follow the format of the other requests
   */

  private static GiopPacketPayload generatePayload(int requestId) {
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

  public static GiopPacket generate(int requestId) {
    return GiopPacket.builder()
            .setVersion(GiopPacket.Version.VERSION_1_0)
            .setType(GiopPacket.Type.GIOP_REQUEST)
            .setIsFragment(false)
            .setZiopSupported(false)
            .setZiopEnabled(false)
            .setIsLittleEndian(false)
            .setPayload(generatePayload(requestId))
            .build();
  }
}
