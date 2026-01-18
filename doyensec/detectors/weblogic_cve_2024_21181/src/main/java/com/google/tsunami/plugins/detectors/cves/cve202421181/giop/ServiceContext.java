package com.google.tsunami.plugins.detectors.cves.cve202421181.giop;

import com.google.auto.value.AutoValue;
import java.nio.ByteBuffer;

@AutoValue
public abstract class ServiceContext {
  public abstract int serviceId();

  public abstract boolean isLittleEndian();

  @SuppressWarnings("mutable")
  public abstract byte[] contextData();

  public int sequenceLength() {
    // Context data + 1 byte for endianness
    return contextData().length + 1;
  }

  public byte[] serialize() {
    int buff_size =
            4 + // serviceId (int) size
            4 + // sequenceLength (int) size
            1 + // Endianness
            contextData().length;

    ByteBuffer buff = ByteBuffer.allocate(buff_size);
    buff.putInt(serviceId());
    buff.putInt(sequenceLength());
    buff.put((byte) (isLittleEndian() ? 1 : 0));
    buff.put(contextData());
    return buff.array();
  }

  public String info() {
    return String.format(
        "ServiceContext[0x%08X]: Data length: %d", serviceId(), sequenceLength() - 1);
  }

  public static ServiceContext deserialize(ByteBuffer buff) {
    int serviceId = buff.getInt();
    int sequenceLength = buff.getInt();
    boolean isLittleEndian = buff.get() == 1;
    byte[] contextData = new byte[sequenceLength - 1];
    buff.get(contextData, 0, sequenceLength - 1);

    return ServiceContext.builder()
        .setServiceId(serviceId)
        .setIsLittleEndian(isLittleEndian)
        .setContextData(contextData)
        .build();
  }

  public static Builder builder() {
    return new AutoValue_ServiceContext.Builder().setIsLittleEndian(false);
  }

  @AutoValue.Builder
  public abstract static class Builder {
    public abstract Builder setServiceId(int serviceId);

    public abstract Builder setIsLittleEndian(boolean isLittleEndian);

    public abstract Builder setContextData(byte[] contextData);

    public abstract ServiceContext build();
  }
}
