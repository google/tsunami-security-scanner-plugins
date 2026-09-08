package com.google.tsunami.plugins.detectors.cves.cve202421181.giop;

import com.google.common.collect.ImmutableList;

public abstract class GiopPacketPayload {
  public abstract GiopPacket.Type type();

  public abstract GiopPacket.Version version();

  public abstract int requestId();

  public abstract ImmutableList<ServiceContext> serviceContextList();

  @SuppressWarnings("mutable")
  public abstract byte[] stubData();

  public abstract String info();
}
