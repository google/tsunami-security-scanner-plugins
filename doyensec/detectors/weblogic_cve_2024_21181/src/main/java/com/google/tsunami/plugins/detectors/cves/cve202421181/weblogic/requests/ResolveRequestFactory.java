package com.google.tsunami.plugins.detectors.cves.cve202421181.weblogic.requests;

import com.google.tsunami.plugins.detectors.cves.cve202421181.Utils;
import com.google.tsunami.plugins.detectors.cves.cve202421181.giop.Giop12Request;
import com.google.tsunami.plugins.detectors.cves.cve202421181.giop.GiopPacket;
import com.google.tsunami.plugins.detectors.cves.cve202421181.giop.GiopRequest;
import java.nio.ByteBuffer;

public class ResolveRequestFactory extends WeblogicIiopRequestFactory {
  private static byte[] generateStubData(String referenceName) {
    int stubDataLength =
        4 // Hardcoded int 1
            + 4 // Refernce name length (int)
            + referenceName.length()
            + Utils.calcBytesToAlign(referenceName.length())
            + 4 // Hardcoded int 1
            + 1; // Single NULL byte

    ByteBuffer buf = ByteBuffer.allocate(stubDataLength);
    buf.putInt((byte) 1);
    buf.putInt(referenceName.length());
    buf.put(referenceName.getBytes());
    buf.put(new byte[Utils.calcBytesToAlign(buf.position())]);
    buf.putInt((byte) 1);
    buf.put((byte) 0x00);
    return buf.array();
  }

  public static GiopPacket generate(int requestId, byte[] keyAddress, String referenceName) {
    return WeblogicIiopRequestFactory.builder()
        .setPayload(
            Giop12Request.builder()
                .setRequestId(requestId)
                .setKeyAddress(keyAddress)
                .setServiceContextList(generateServiceContexts())
                .setOperation(GiopRequest.Operation.OP_RESOLVE_ANY)
                .setStubData(generateStubData(referenceName))
                .build())
        .build();
  }
}
