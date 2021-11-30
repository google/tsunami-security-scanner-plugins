/*
 * Copyright 2021 Facebook
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.google.tsunami.plugins.detectors.rce.ciscosmi;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;

import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.common.net.HostAndPort;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkEndpointUtils;
import com.google.tsunami.common.time.UtcClock;
import com.google.tsunami.plugin.PluginType;
import com.google.tsunami.plugin.VulnDetector;
import com.google.tsunami.plugin.annotations.ForServiceName;
import com.google.tsunami.plugin.annotations.PluginInfo;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.Vulnerability;
import com.google.tsunami.proto.VulnerabilityId;
import java.net.Socket;
import java.time.Clock;
import java.time.Instant;
import java.util.Arrays;
import javax.inject.Inject;
import javax.net.SocketFactory;

/** A {@link VulnDetector} that detects vulnerable Cisco Smart Install protocol */
@ForServiceName({"smart-install"})
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "Cisco_SMI",
    version = "0.1",
    description = "This detector checks for Cisco Smart Install client protocol.",
    author = "Adrien Schildknecht (vulnscan@fb.com)",
    bootstrapModule = CiscoSMIDetectorBootstrapModule.class)
public final class CiscoSMIDetector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private final Clock utcClock;
  private final SocketFactory socketFactory;

  @Inject
  public CiscoSMIDetector(@UtcClock Clock utcClock, SocketFactory socketFactory) {
    this.utcClock = checkNotNull(utcClock);
    this.socketFactory = checkNotNull(socketFactory);
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    return DetectionReportList.newBuilder()
        .addAllDetectionReports(
            matchedServices.stream()
                .filter(this::isServiceVulnerable)
                .map(networkService -> buildDetectionReport(targetInfo, networkService))
                .collect(toImmutableList()))
        .build();
  }

  private boolean isServiceVulnerable(NetworkService networkService) {
    byte[] actualResponse = new byte[24];
    // See https://github.com/Cisco-Talos/smi_check for more info about the payload
    byte[] request = {
      0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
      0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x08,
      0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    };
    byte[] expectedResponse = {
      0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x08,
      0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    };
    HostAndPort hp = NetworkEndpointUtils.toHostAndPort(networkService.getNetworkEndpoint());

    try {
      Socket socket = socketFactory.createSocket(hp.getHost(), hp.getPort());
      socket.setSoTimeout(2000);
      socket.getOutputStream().write(request);
      socket.getInputStream().read(actualResponse, 0, actualResponse.length);
      socket.close();
    } catch (Exception e) {
      logger.atWarning().withCause(e).log("Unable to communicate with '%s'.", hp.toString());
      return false;
    }

    if (Arrays.equals(actualResponse, expectedResponse)) {
      return true;
    } else if (actualResponse.length < 1) {
      logger.atInfo().log("SMI is enabled but not vulnerable");
    }
    return false;
  }

  private DetectionReport buildDetectionReport(
      TargetInfo scannedTarget, NetworkService vulnerableNetworkService) {
    return DetectionReport.newBuilder()
        .setTargetInfo(scannedTarget)
        .setNetworkService(vulnerableNetworkService)
        .setDetectionTimestamp(Timestamps.fromMillis(Instant.now(utcClock).toEpochMilli()))
        .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
        .setVulnerability(
            Vulnerability.newBuilder()
                .setMainId(
                    VulnerabilityId.newBuilder()
                        .setPublisher("CISCO")
                        .setValue("CISCO_SA_20170214_SMI"))
                .setSeverity(Severity.HIGH)
                .setTitle("Cisco Smart Install Protocol Misuse")
                .setDescription(
                    "Cisco Smart Install feature should not be exposed as it enables attackers to"
                        + " perform administrative tasks on the device or remotely execute code"))
        .build();
  }
}
