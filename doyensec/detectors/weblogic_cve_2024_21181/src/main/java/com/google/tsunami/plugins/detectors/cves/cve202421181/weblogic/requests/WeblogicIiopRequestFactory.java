package com.google.tsunami.plugins.detectors.cves.cve202421181.weblogic.requests;

import com.google.common.collect.ImmutableList;
import com.google.tsunami.plugins.detectors.cves.cve202421181.Utils;
import com.google.tsunami.plugins.detectors.cves.cve202421181.giop.GiopPacket;
import com.google.tsunami.plugins.detectors.cves.cve202421181.giop.ServiceContext;

public abstract class WeblogicIiopRequestFactory {
  /*
  Common values shared among all WebLogic request packets
   */

  protected static ImmutableList<ServiceContext> generateServiceContexts() {
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

  protected static GiopPacket.Builder builder() {
    return GiopPacket.builder()
            .setVersion(GiopPacket.Version.VERSION_1_2)
            .setType(GiopPacket.Type.GIOP_REQUEST)
            .setIsFragment(false)
            .setZiopSupported(false)
            .setZiopEnabled(false)
            .setIsLittleEndian(false);
  }
}
