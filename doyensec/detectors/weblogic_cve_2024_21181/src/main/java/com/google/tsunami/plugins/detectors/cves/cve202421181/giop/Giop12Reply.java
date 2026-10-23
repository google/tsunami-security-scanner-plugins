package com.google.tsunami.plugins.detectors.cves.cve202421181.giop;

import com.google.auto.value.AutoValue;
import com.google.common.base.Optional;
import com.google.common.collect.ImmutableList;
import com.google.tsunami.plugins.detectors.cves.cve202421181.Utils;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

@AutoValue
public abstract class Giop12Reply extends GiopReply {
  @Override
  public GiopPacket.Version version() {
    return GiopPacket.Version.VERSION_1_2;
  }

  public abstract Optional<IorReference> iorReference();

  public String info() {
    StringBuilder builder = new StringBuilder();
    builder.append(
        String.format(
            "GIOP 1.2 Reply: Request ID: %d, Status: %s, Stub Data: %d, Service Contexts: %d, IOR:"
                + " %s\n",
            requestId(),
            replyStatus().name(),
            stubData().length,
            serviceContextList().size(),
            iorReference().isPresent() ? "Present" : "Not present"));
    for (ServiceContext serviceContext : serviceContextList()) {
      builder.append(serviceContext.info());
      builder.append("\n");
    }
    return builder.toString();
  }

  public static Giop12Reply deserialize(ByteBuffer buffer) {
    int requestId = buffer.getInt();
    int replyStatusInt = buffer.getInt();
    ReplyStatus replyStatus = replyStatusFromInt(replyStatusInt);

    // Deserialize serviceContexts
    int serviceContextListSize = buffer.getInt();
    List<ServiceContext> serviceContextList = new ArrayList<ServiceContext>(serviceContextListSize);
    for (int i = 0; i < serviceContextListSize; i++) {
      serviceContextList.add(ServiceContext.deserialize(buffer));
      Utils.alignByteBuf(buffer);
    }

    // Get IOR Reference
    Optional<IorReference> iorReferenceOptional;
    if (replyStatus == ReplyStatus.STATUS_LOCATION_FORWARD) {
      IorReference iorReference = IorReference.deserialize(buffer);
      iorReferenceOptional = Optional.of(iorReference);
    } else {
      iorReferenceOptional = Optional.absent();
    }

    // Stub data
    byte[] stubData = new byte[buffer.remaining()];
    buffer.get(stubData);

    return builder()
        .setRequestId(requestId)
        .setReplyStatus(replyStatus)
        .setServiceContextList(ImmutableList.copyOf(serviceContextList))
        .setIorReference(iorReferenceOptional)
        .setStubData(stubData)
        .build();
  }

  public static Giop12Reply.Builder builder() {
    return new AutoValue_Giop12Reply.Builder();
  }

  @AutoValue.Builder
  public abstract static class Builder {
    public abstract Giop12Reply.Builder setReplyStatus(ReplyStatus status);

    public abstract Giop12Reply.Builder setRequestId(int requestId);

    public abstract Giop12Reply.Builder setServiceContextList(
        ImmutableList<ServiceContext> serviceContextList);

    public abstract Giop12Reply.Builder setStubData(byte[] stubData);

    public abstract Giop12Reply.Builder setIorReference(Optional<IorReference> iorReference);

    public abstract Giop12Reply build();
  }
}
