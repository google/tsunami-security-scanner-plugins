package com.google.tsunami.plugins.detectors.cves.cve202421181.giop;

import com.google.auto.value.AutoValue;
import com.google.common.collect.ImmutableList;
import com.google.tsunami.plugins.detectors.cves.cve202421181.Utils;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

@AutoValue
public abstract class Giop12Request extends GiopRequest {
  public static byte RESPONSE_FLAGS = 3;
  public static short TARGET_ADDRESS_KEY = 0;

  @SuppressWarnings("mutable")
  public abstract byte[] keyAddress();

  @Override
  public GiopPacket.Version version() {
    return GiopPacket.Version.VERSION_1_2;
  }

  public String info() {
    StringBuilder builder = new StringBuilder();
    builder.append(
        String.format(
            "GIOP 1.2 Request: Request ID: %d, OP: %s, Stub Data: %d, Service Contexts: %d\n",
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

    // Calculate size
    int bufSize =
        4 // Request ID
            + 1 // Response flags
            + 3 // Reserved
            + 2
            + 2 // Target Address + alignment
            + 4 // Key address length
            + keyAddress().length
            + Utils.calcBytesToAlign(keyAddress().length)
            + 4 // Operation length
            + operationAsBytes().length
            + Utils.calcBytesToAlign(operationAsBytes().length)
            + 4 // ServiceContextList length
            + serviceContextListSize
            + (stubData().length > 0 ? 4 : 0) // 4 B of padding, only if stubData is present
            + stubData().length;

    // Allocate buffer and write the data
    ByteBuffer buf = ByteBuffer.allocate(bufSize);

    buf.putInt(requestId());

    buf.put(RESPONSE_FLAGS);
    buf.put(new byte[3]); // Reserved

    buf.putShort(TARGET_ADDRESS_KEY);
    buf.put(new byte[2]); // Padding

    buf.putInt(keyAddress().length);
    buf.put(keyAddress());
    buf.put(new byte[Utils.calcBytesToAlign(keyAddress().length)]); // Padding

    buf.putInt(operationAsBytes().length);
    buf.put(operationAsBytes());
    buf.put(new byte[Utils.calcBytesToAlign(operationAsBytes().length)]); // Padding

    buf.putInt(serializedContexts.size());
    for (byte[] serializedContext : serializedContexts) {
      buf.put(serializedContext);
      buf.put(new byte[Utils.calcBytesToAlign(serializedContext.length)]); // Padding
    }
    if (stubData().length > 0) {
      buf.put(new byte[4]); // Padding
    }
    buf.put(stubData());

    return buf.array();
  }

  public static Giop12Request.Builder builder() {
    return new AutoValue_Giop12Request.Builder();
  }

  @AutoValue.Builder
  public abstract static class Builder {
    public abstract Giop12Request.Builder setRequestId(int requestId);

    public abstract Giop12Request.Builder setOperation(Operation operation);

    public abstract Giop12Request.Builder setServiceContextList(
        ImmutableList<ServiceContext> serviceContextList);

    public abstract Giop12Request.Builder setStubData(byte[] stubData);

    public abstract Giop12Request.Builder setKeyAddress(byte[] keyAddress);

    public abstract Giop12Request build();
  }
}
