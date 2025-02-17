package com.google.tsunami.plugins.detectors.cves.cve202421181.weblogic.requests;

import com.google.tsunami.plugins.detectors.cves.cve202421181.Utils;
import com.google.tsunami.plugins.detectors.cves.cve202421181.giop.Giop12Request;
import com.google.tsunami.plugins.detectors.cves.cve202421181.giop.GiopPacketPayload;
import com.google.tsunami.plugins.detectors.cves.cve202421181.giop.GiopRequest;
import java.nio.ByteBuffer;

public class ResolveRequest extends WeblogicIiopRequest {
  private final String referenceName;

  public ResolveRequest(int requestId, byte[] keyAddress, String referenceName) {
    super(requestId, keyAddress);
    this.referenceName = referenceName;
  }

  private byte[] generateStubData() {
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

  @Override
  public GiopPacketPayload payload() {
    return Giop12Request.builder()
        .setRequestId(requestId)
        .setKeyAddress(keyAddress)
        .setServiceContextList(generateServiceContexts())
        .setOperation(GiopRequest.Operation.OP_RESOLVE_ANY)
        .setStubData(generateStubData())
        .build();
  }
}
