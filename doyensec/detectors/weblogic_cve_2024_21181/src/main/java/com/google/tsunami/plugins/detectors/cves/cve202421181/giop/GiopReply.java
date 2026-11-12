package com.google.tsunami.plugins.detectors.cves.cve202421181.giop;

public abstract class GiopReply extends GiopPacketPayload {
  public enum ReplyStatus {
    STATUS_NO_EXCEPTION,
    STATUS_USER_EXCEPTION,
    STATUS_SYSTEM_EXCEPTION,
    STATUS_LOCATION_FORWARD,
    STATUS_NOT_IMPLEMENTED
  }

  public abstract ReplyStatus replyStatus();

  static ReplyStatus replyStatusFromInt(int replyStatus) {
    switch (replyStatus) {
      case 0:
        return ReplyStatus.STATUS_NO_EXCEPTION;
      case 1:
        return ReplyStatus.STATUS_USER_EXCEPTION;
      case 2:
        return ReplyStatus.STATUS_SYSTEM_EXCEPTION;
      case 3:
        return ReplyStatus.STATUS_LOCATION_FORWARD;
      default:
        return ReplyStatus.STATUS_NOT_IMPLEMENTED;
    }
  }

  @Override
  public GiopPacket.Type type() {
    return GiopPacket.Type.GIOP_REPLY;
  }
}
