package com.google.tsunami.plugins.detectors.cves.cve202421181.weblogic.requests;

import com.google.common.collect.ImmutableList;
import com.google.tsunami.plugins.detectors.cves.cve202421181.Utils;
import com.google.tsunami.plugins.detectors.cves.cve202421181.giop.GiopPacket;
import com.google.tsunami.plugins.detectors.cves.cve202421181.giop.ServiceContext;

public abstract class WeblogicIiopRequest extends GiopPacket {
  /*
  Common values shared among all WebLogic request packets
   */
  protected byte[] keyAddress;
  protected int requestId;

  public WeblogicIiopRequest(int requestId, byte[] keyAddress) {
    this.requestId = requestId;
    this.keyAddress = keyAddress;
  }

  @Override
  public Version version() {
    return Version.VERSION_1_2;
  }

  @Override
  public Type type() {
    return Type.GIOP_REQUEST;
  }

  @Override
  public boolean isLittleEndian() {
    return false;
  }

  @Override
  public boolean ziopEnabled() {
    return false;
  }

  @Override
  public boolean ziopSupported() {
    return false;
  }

  @Override
  public boolean isFragment() {
    return false;
  }

  protected ImmutableList<ServiceContext> generateServiceContexts() {
    ServiceContext serviceContext1 =
        ServiceContext.builder()
            .setServiceId(0x11) // Unknown
            .setContextData(new byte[] {0x02})
            .build();

    ServiceContext serviceContext2 =
        ServiceContext.builder()
            .setServiceId(0x01) // "CodeSets"
            .setContextData(Utils.hexStringToByteArray("0000000001002005010001"))
            .build();

    ServiceContext serviceContext3 =
        ServiceContext.builder().setServiceId(0x4e454f00).setContextData(new byte[] {0x14}).build();

    ServiceContext serviceContext4 =
        ServiceContext.builder()
            .setServiceId(0x42454100)
            .setContextData(Utils.hexStringToByteArray("0C020104"))
            .build();

    return ImmutableList.of(serviceContext1, serviceContext2, serviceContext3, serviceContext4);
  }
}
