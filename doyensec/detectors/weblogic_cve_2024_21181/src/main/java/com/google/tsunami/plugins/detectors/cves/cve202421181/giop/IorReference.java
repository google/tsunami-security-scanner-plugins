package com.google.tsunami.plugins.detectors.cves.cve202421181.giop;

import com.google.auto.value.AutoValue;
import com.google.common.collect.ImmutableList;
import com.google.tsunami.plugins.detectors.cves.cve202421181.Utils;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import org.apache.commons.lang3.tuple.ImmutablePair;

@AutoValue
public abstract class IorReference {
  public abstract String typeId();

  public abstract int profileId();

  public abstract boolean isLittleEndian();

  public abstract int majorVersion();

  public abstract int minorVersion();

  public abstract String profileHost();

  public abstract int profilePort();

  @SuppressWarnings("mutable")
  public abstract byte[] objectKey();

  public abstract ImmutableList<ImmutablePair<Integer, byte[]>> components();

  public static IorReference deserialize(ByteBuffer buffer) {
    // Type ID
    int typeIdLength = buffer.getInt();
    byte[] typeId = new byte[typeIdLength];
    buffer.get(typeId, 0, typeIdLength);
    int padding = Utils.calcBytesToAlign(typeIdLength);
    buffer.position(buffer.position() + padding);

    buffer.getInt(); // sequence length

    // Profile ID
    int profileId = buffer.getInt();

    // Remaining packet length
    int packetLength = buffer.getInt();

    // Endianness
    boolean isLittleEndian = buffer.get() != 0;

    // IIOP Version
    int majorVersion = buffer.get();
    int minorVersion = buffer.get();
    buffer.get(); // Padding

    // Profile host + port
    int profileHostLength = buffer.getInt();
    byte[] profileHost = new byte[profileHostLength];
    buffer.get(profileHost, 0, profileHostLength);
    int profilePort = buffer.getShort();
    padding = Utils.calcBytesToAlign(profileHostLength + 2); // Host + port
    buffer.position(buffer.position() + padding);

    // Object key
    int objectKeyLength = buffer.getInt();
    byte[] objectKey = new byte[objectKeyLength];
    buffer.get(objectKey, 0, objectKeyLength);
    padding = Utils.calcBytesToAlign(objectKeyLength); // Host + port
    buffer.position(buffer.position() + padding);

    // IIOP Components Data
    int componentsLength = buffer.getInt();
    List<ImmutablePair<Integer, byte[]>> components = new ArrayList<>();
    for (int i = 0; i < componentsLength; i++) {
      // Account for optional padding
      padding = Utils.calcBytesToAlign(buffer.position());
      buffer.position(buffer.position() + padding);

      // Get component tag and data
      int componentTag = buffer.getInt();
      int componentDataLength = buffer.getInt();
      byte[] componentData = new byte[componentDataLength];
      buffer.get(componentData, 0, componentDataLength);
      components.add(ImmutablePair.of(componentTag, componentData));
    }

    return builder()
        .setTypeId(new String(typeId, StandardCharsets.UTF_8))
        .setProfileId(profileId)
        .setIsLittleEndian(isLittleEndian)
        .setMajorVersion(majorVersion)
        .setMinorVersion(minorVersion)
        .setProfileHost(new String(profileHost, StandardCharsets.UTF_8))
        .setProfilePort(profilePort)
        .setObjectKey(objectKey)
        .setComponents(ImmutableList.copyOf(components))
        .build();
  }

  public static Builder builder() {
    return new AutoValue_IorReference.Builder();
  }

  @AutoValue.Builder
  public abstract static class Builder {
    public abstract Builder setTypeId(String typeId);

    public abstract Builder setProfileId(int profileId);

    public abstract Builder setIsLittleEndian(boolean isLittleEndian);

    public abstract Builder setMajorVersion(int majorVersion);

    public abstract Builder setMinorVersion(int minorVersion);

    public abstract Builder setProfileHost(String profileHost);

    public abstract Builder setProfilePort(int profilePort);

    public abstract Builder setObjectKey(byte[] objectKey);

    public abstract Builder setComponents(ImmutableList<ImmutablePair<Integer, byte[]>> components);

    public abstract IorReference build();
  }
}
