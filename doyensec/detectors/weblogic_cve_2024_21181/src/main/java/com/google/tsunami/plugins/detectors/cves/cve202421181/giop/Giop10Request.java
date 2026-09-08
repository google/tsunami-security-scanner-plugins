package com.google.tsunami.plugins.detectors.cves.cve202421181.giop;

import com.google.auto.value.AutoValue;
import com.google.common.collect.ImmutableList;
import com.google.tsunami.plugins.detectors.cves.cve202421181.Utils;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

@AutoValue
public abstract class Giop10Request extends GiopRequest {
  public enum ObjectKey {
    KEY_INIT
  }

  protected byte[] objectKeyAsBytes() {
    switch (objectKey()) {
      case KEY_INIT:
        return "INIT".getBytes();
      default:
        throw new AssertionError();
    }
  }

  @Override
  public GiopPacket.Version version() {
    return GiopPacket.Version.VERSION_1_0;
  }

  public abstract boolean responseExpected();

  public abstract ObjectKey objectKey();

  public abstract int requestingPrincipalLength();

  public String info() {
    StringBuilder builder = new StringBuilder();
    builder.append(
        String.format(
            "GIOP 1.0 Request: Request ID: %d, OP: %s, Stub Data: %d, Service Contexts: %d\n",
            requestId(), operation().name(), stubData().length, serviceContextList().size()));
    for (ServiceContext serviceContext : serviceContextList()) {
      builder.append(serviceContext.info());
      builder.append("\n");
    }
    return builder.toString();
  }

  @Override
  public byte[] serialize() {
    // Serialize service contexts first
    int serviceContextListSize = 0;
    List<byte[]> serializedContexts = new ArrayList<byte[]>();
    for (ServiceContext serviceContext : serviceContextList()) {
      byte[] serialized = serviceContext.serialize();
      serializedContexts.add(serialized);
      serviceContextListSize += serialized.length;
      serviceContextListSize += Utils.calcBytesToAlign(serialized.length);
    }

    // Get Object Key as bytes
    byte[] objectKeyAsBytes = objectKeyAsBytes();

    // Get Operation as bytes
    byte[] operationAsBytes = operationAsBytes();

    int bufSize =
            4 + // serviceContextList item count
            serviceContextListSize +
            4 + // Request ID (int)
            4 + // response expected (bool) + 3 B alignment
            4 + // Object key length (int)
            objectKeyAsBytes.length +
            4 + // Operation length (int)
            operationAsBytes.length +
            4 + // RequestingPrincipal Length
            stubData().length;

    ByteBuffer buf = ByteBuffer.allocate(bufSize);
    buf.putInt(serializedContexts.size());
    for (byte[] serializedContext : serializedContexts) {
      buf.put(serializedContext);

      // Make sure to add alignment bytes
      int alignmentBytes = Utils.calcBytesToAlign(serializedContext.length);
      for (int i = 0; i < alignmentBytes; i++) {
        buf.put((byte) 0);
      }
    }
    buf.putInt(requestId());
    buf.put((byte) (responseExpected() ? 1 : 0));
    buf.put((byte) 0x00); //
    buf.put((byte) 0x00); // Align to boundary
    buf.put((byte) 0x00); //
    buf.putInt(objectKeyAsBytes.length);
    buf.put(objectKeyAsBytes);
    buf.putInt(operationAsBytes.length);
    buf.put(operationAsBytes);
    buf.putInt(requestingPrincipalLength());
    buf.put(stubData());
    return buf.array();
  }

  public static Giop10Request.Builder builder() {
    return new AutoValue_Giop10Request.Builder()
        .setRequestingPrincipalLength(0)
        .setObjectKey(ObjectKey.KEY_INIT)
        .setResponseExpected(true)
        .setServiceContextList(ImmutableList.of())
        .setStubData(new byte[0]);
  }

  @AutoValue.Builder
  public abstract static class Builder {
    public abstract Giop10Request.Builder setRequestingPrincipalLength(
        int requestingPrincipalLength);

    public abstract Giop10Request.Builder setResponseExpected(boolean responseExpected);

    public abstract Giop10Request.Builder setObjectKey(ObjectKey objectKey);

    public abstract Giop10Request.Builder setRequestId(int requestId);

    public abstract Giop10Request.Builder setOperation(Operation operation);

    public abstract Giop10Request.Builder setServiceContextList(
        ImmutableList<ServiceContext> serviceContextList);

    public abstract Giop10Request.Builder setStubData(byte[] stubData);

    public abstract Giop10Request build();
  }
}
