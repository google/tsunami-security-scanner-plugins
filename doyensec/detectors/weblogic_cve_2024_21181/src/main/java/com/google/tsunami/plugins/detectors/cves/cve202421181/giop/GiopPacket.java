package com.google.tsunami.plugins.detectors.cves.cve202421181.giop;

import com.google.auto.value.AutoValue;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

@AutoValue
public abstract class GiopPacket {
  public enum Type {
    GIOP_REQUEST,
    GIOP_REPLY,
  }

  public enum Version {
    VERSION_1_0,
    VERSION_1_2,
  }

  // Packet header
  public abstract Version version();

  public abstract Type type();

  // Message flags
  public abstract boolean isLittleEndian();

  public abstract boolean ziopEnabled();

  public abstract boolean ziopSupported();

  public abstract boolean isFragment();

  // Payload
  public abstract GiopPacketPayload payload();

  public String info() {
    StringBuilder sb = new StringBuilder();
    String type = type() == Type.GIOP_REQUEST ? "REQUEST" : "REPLY";
    String version = version() == Version.VERSION_1_0 ? "1.0" : "1.2";
    sb.append(String.format("GIOP packet: Type: %s, Version: %s\n", type, version));
    sb.append(payload().info());
    sb.append("\n");
    return sb.toString();
  }

  public byte[] serialize() {
    if (type() != Type.GIOP_REQUEST || payload().type() != Type.GIOP_REQUEST) {
      throw new IllegalArgumentException("serialize() only supported for GIOP requests");
    }

    byte[] serializedPacketPayload = ((GiopRequest) payload()).serialize();
    int packetLength =
            4 + // "GIOP" magic value
            2 + // Major + Minor version number
            1 + // Flags
            1 + // Type
            4 + // payload size (int)
            serializedPacketPayload.length;

    ByteBuffer buffer = ByteBuffer.allocate(packetLength);
    // Magic
    buffer.put("GIOP".getBytes(StandardCharsets.UTF_8));

    // Version
    buffer.put((byte) 1);
    if (version() == Version.VERSION_1_0) {
      buffer.put((byte) 0);
    } else if (version() == Version.VERSION_1_2) {
      buffer.put((byte) 2);
    } else {
      throw new IllegalArgumentException("Unsupported version: " + version());
    }

    // Flags
    int ziopEnabledFlag = ziopEnabled() ? 1 : 0;
    int ziopSupportedFlag = ziopSupported() ? 1 : 0;
    int isFragmentFlag = isFragment() ? 1 : 0;
    int isLittleEndianFlag = isLittleEndian() ? 1 : 0;
    byte flags =
        (byte)
            (ziopEnabledFlag << 3
                | ziopSupportedFlag << 2
                | isFragmentFlag << 1
                | isLittleEndianFlag);
    buffer.put(flags);

    // Message type
    if (type() == Type.GIOP_REQUEST) {
      buffer.put((byte) 0);
    } else {
      buffer.put((byte) 1);
    }

    // Payload
    buffer.putInt(serializedPacketPayload.length);
    buffer.put(serializedPacketPayload);

    return buffer.array();
  }

  public static GiopPacket deserialize(ByteBuffer buffer) {
    // Check magic
    byte[] magic = new byte[4];
    buffer.get(magic, 0, 4);
    if (!new String(magic, StandardCharsets.UTF_8).equals("GIOP")) {
      throw new RuntimeException("Wrong magic in packet: protocol not GIOP.");
    }

    // Get packet version
    int majorVersion = buffer.get() & 0xFF;
    int minorVersion = buffer.get() & 0xFF;
    if (majorVersion != 1) {
      throw new RuntimeException(
          String.format("GIOP major version not supported: %d.%d", majorVersion, minorVersion));
    }
    Version version;
    if (minorVersion == 0) {
      version = Version.VERSION_1_0;
    } else if (minorVersion == 2) {
      version = Version.VERSION_1_2;
    } else {
      throw new RuntimeException(
          String.format("GIOP minor version not supported: %d.%d", majorVersion, minorVersion));
    }

    // Get flags
    byte flags = buffer.get();
    boolean ziopEnabled = (flags & 0b00001000) >> 3 == 1;
    boolean ziopSupported = (flags & 0b00000100) >> 2 == 1;
    boolean isFragment = (flags & 0b00000010) >> 1 == 1;
    boolean isLittleEndian = (flags & 0b00000001) == 1;

    // Get message type
    byte typeByte = buffer.get();
    Type type;
    if (typeByte == 0) {
      type = Type.GIOP_REQUEST;
    } else if (typeByte == 1) {
      type = Type.GIOP_REPLY;
    } else {
      throw new IllegalArgumentException("Unsupported type: " + typeByte);
    }

    // Only deserialize replies for now
    if (type == Type.GIOP_REQUEST) {
      throw new RuntimeException("Deserializing GIOP requests is not supported.");
    }

    // Payload length
    int payloadLength = buffer.getInt();

    // Set the buffer limit to the size of the remaining bytes
    buffer.limit(buffer.position() + payloadLength);

    // Deserialize payload
    GiopPacketPayload payload;
    if (version == Version.VERSION_1_0) {
      payload = Giop10Reply.deserialize(buffer);
    } else {
      payload = Giop12Reply.deserialize(buffer);
    }

    return builder()
        .setType(type)
        .setVersion(version)
        .setZiopEnabled(ziopEnabled)
        .setZiopSupported(ziopSupported)
        .setIsFragment(isFragment)
        .setIsLittleEndian(isLittleEndian)
        .setPayload(payload)
        .build();
  }

  public static GiopPacket.Builder builder() {
    return new AutoValue_GiopPacket.Builder()
        .setZiopEnabled(false)
        .setZiopSupported(false)
        .setIsFragment(false)
        .setIsLittleEndian(false);
  }

  @AutoValue.Builder
  public abstract static class Builder {
    public abstract GiopPacket.Builder setVersion(Version version);

    public abstract GiopPacket.Builder setType(Type type);

    public abstract GiopPacket.Builder setZiopEnabled(boolean ziopEnabled);

    public abstract GiopPacket.Builder setIsLittleEndian(boolean isLittleEndian);

    public abstract GiopPacket.Builder setZiopSupported(boolean ziopSupported);

    public abstract GiopPacket.Builder setIsFragment(boolean fragment);

    public abstract GiopPacket.Builder setPayload(GiopPacketPayload payload);

    public abstract GiopPacket build();
  }
}
