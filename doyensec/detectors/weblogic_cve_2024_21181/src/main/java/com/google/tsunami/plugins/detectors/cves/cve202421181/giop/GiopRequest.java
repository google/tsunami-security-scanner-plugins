package com.google.tsunami.plugins.detectors.cves.cve202421181.giop;

import java.nio.charset.StandardCharsets;
import org.apache.commons.lang.NotImplementedException;

public abstract class GiopRequest extends GiopPacketPayload {
  public enum Operation {
    OP_GET,
    OP_REBIND_ANY,
    OP_RESOLVE_ANY,
    OP_NON_EXISTENT
  }

  @Override
  public GiopPacket.Type type() {
    return GiopPacket.Type.GIOP_REQUEST;
  }

  public abstract byte[] serialize();

  public abstract Operation operation();

  protected byte[] operationAsBytes() {
    switch (operation()) {
      case OP_GET:
        return "get\0".getBytes(StandardCharsets.UTF_8);
      case OP_REBIND_ANY:
        return "rebind_any\0".getBytes(StandardCharsets.UTF_8);
      case OP_RESOLVE_ANY:
        return "resolve_any\0".getBytes(StandardCharsets.UTF_8);
      case OP_NON_EXISTENT:
        return "_non_existent\0".getBytes(StandardCharsets.UTF_8);
      default:
        throw new NotImplementedException("Unknown operation: " + operation());
    }
  }
}
