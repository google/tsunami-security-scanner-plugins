package com.google.tsunami.plugins.detectors.cves.cve202421181.giop;

import com.google.auto.value.AutoValue;
import com.google.common.collect.ImmutableList;
import com.google.tsunami.plugins.detectors.cves.cve202421181.Utils;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

@AutoValue
public abstract class Giop10Reply extends GiopReply {

  @Override
  public GiopPacket.Version version() {
    return GiopPacket.Version.VERSION_1_0;
  }

  public String info() {
    StringBuilder builder = new StringBuilder();
    builder.append(
        String.format(
            "GIOP 1.0 Reply: Request ID: %d, Status: %s, Stub Data: %d, Service Contexts: %d\n",
            requestId(), replyStatus().name(), stubData().length, serviceContextList().size()));
    for (ServiceContext serviceContext : serviceContextList()) {
      builder.append(serviceContext.info());
      builder.append("\n");
    }
    return builder.toString();
  }

  public static Giop10Reply deserialize(ByteBuffer buffer) {
    // Deserialize serviceContexts
    int serviceContextListSize = buffer.getInt();
    List<ServiceContext> serviceContextList = new ArrayList<ServiceContext>(serviceContextListSize);
    for (int i = 0; i < serviceContextListSize; i++) {
      serviceContextList.add(ServiceContext.deserialize(buffer));
      Utils.alignByteBuf(buffer);
    }

    int requestId = buffer.getInt();
    int replyStatusInt = buffer.getInt();
    ReplyStatus replyStatus = replyStatusFromInt(replyStatusInt);
    byte[] stubData = new byte[buffer.remaining()];
    buffer.get(stubData);

    return builder()
        .setRequestId(requestId)
        .setReplyStatus(replyStatus)
        .setServiceContextList(ImmutableList.copyOf(serviceContextList))
        .setStubData(stubData)
        .build();
  }

  public static Giop10Reply.Builder builder() {
    return new AutoValue_Giop10Reply.Builder();
  }

  @AutoValue.Builder
  public abstract static class Builder {
    public abstract Giop10Reply.Builder setReplyStatus(ReplyStatus status);

    public abstract Giop10Reply.Builder setRequestId(int requestId);

    public abstract Giop10Reply.Builder setServiceContextList(
        ImmutableList<ServiceContext> serviceContextList);

    public abstract Giop10Reply.Builder setStubData(byte[] stubData);

    public abstract Giop10Reply build();
  }
}
