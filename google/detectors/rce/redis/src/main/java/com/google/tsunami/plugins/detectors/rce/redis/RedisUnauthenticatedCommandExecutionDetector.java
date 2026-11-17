/*
 * Copyright 2021 Google LLC
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
package com.google.tsunami.plugins.detectors.rce.redis;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.common.net.HostAndPort;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkEndpointUtils;
import com.google.tsunami.common.net.socket.TsunamiSocketFactory;
import com.google.tsunami.common.time.UtcClock;
import com.google.tsunami.plugin.PluginType;
import com.google.tsunami.plugin.VulnDetector;
import com.google.tsunami.plugin.annotations.ForServiceName;
import com.google.tsunami.plugin.annotations.PluginInfo;
import com.google.tsunami.proto.AdditionalDetail;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.TextData;
import com.google.tsunami.proto.TransportProtocol;
import com.google.tsunami.proto.Vulnerability;
import com.google.tsunami.proto.VulnerabilityId;
import java.net.Socket;
import java.time.Clock;
import java.time.Instant;
import javax.inject.Inject;

/** Detects unauthenticated Redis protocol command access and potential RCE escalation paths. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "RedisUnauthenticatedCommandExecutionDetector",
    version = "0.2",
    description = "Detects Redis unauthenticated command execution.",
    author = "Oleksii Prokopchuk (prokopchuk@google.com)",
    bootstrapModule = RedisUnauthenticatedCommandExecutionDetectorBootstrapModule.class)
@ForServiceName({"redis"})
public final class RedisUnauthenticatedCommandExecutionDetector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  static final String VULN_DESCRIPTION =
      "The scanner executed the Redis \"INFO server\" command without authentication and observed"
          + " \"redis_version:\" in the response (an authenticated instance returns \"-NOAUTH"
          + " Authentication required.\"). Despite the legacy"
          + " REDIS_UNAUTHENTICATED_COMMAND_EXECUTION identifier, this check confirms"
          + " unauthenticated Redis protocol command access rather than guaranteed OS shell"
          + " execution.\n"
          + "\n"
          + "Impact on any unauthenticated Redis instance (including Redis >= 7.0 and Valkey with"
          + " default protected-config and module restrictions):\n"
          + "- Data read/write and secret exposure: Full read, modification, and deletion"
          + " (FLUSHALL) of keys, session tokens, and queues, plus live traffic capture when"
          + " MONITOR is permitted.\n"
          + "- Application-layer RCE via unsafe deserialization: Poisoning keys or job queues"
          + " consumed by workers using Python pickle (Celery, RQ, Django), Ruby Marshal"
          + " (Sidekiq, Rails), Java serialization/Kryo, or PHP session handlers can achieve"
          + " remote code execution on downstream application hosts.\n"
          + "- Internal network SSRF: If REPLICAOF/SLAVEOF or MIGRATE is permitted, an attacker"
          + " can force outbound TCP connections from the Redis host to internal VPC endpoints.\n"
          + "\n"
          + "Direct Redis-server OS RCE (version- and configuration-dependent):\n"
          + "- Escalating directly to OS command execution on the Redis host requires Redis < 7.0"
          + " (or relaxed enable-protected-configs / enable-module-command settings) permitting"
          + " CONFIG SET dir/dbfilename, MODULE LOAD, or rogue-primary replication, or an"
          + " unpatched engine/Lua vulnerability (such as CVE-2022-0543 or CVE-2025-49844).";

  static final String VULN_RECOMMENDATION =
      "1. Restrict network reachability so only trusted clients can connect (bind to loopback or"
          + " private VPC interfaces, enforce firewall rules, and keep protected-mode yes).\n"
          + "2. Require strong authentication via Redis ACLs (configure ACL SETUSER in users.acl"
          + " to disable or restrict the default user and block @admin, @dangerous, and"
          + " @scripting commands where unneeded) or set requirepass in redis.conf.\n"
          + "3. Keep enable-protected-configs no and enable-module-command no (the default in"
          + " Redis >= 7.0 and Valkey), enable TLS on untrusted networks, and keep the Redis or"
          + " Valkey server patched:\n"
          + "https://redis.io/docs/latest/operate/oss_and_stack/management/security/";

  private final Clock utcClock;
  private final TsunamiSocketFactory socketFactory;

  @Inject
  RedisUnauthenticatedCommandExecutionDetector(
      @UtcClock Clock utcClock, TsunamiSocketFactory socketFactory) {
    this.utcClock = checkNotNull(utcClock);
    this.socketFactory = checkNotNull(socketFactory);
  }

  private static class ProbingDetails {
    String response;
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    ProbingDetails probingDetails = new ProbingDetails();
    return DetectionReportList.newBuilder()
        .addAllDetectionReports(
            matchedServices.stream()
                .filter(this::isTransportProtocolTcp)
                .filter(networkService -> isServiceVulnerable(networkService, probingDetails))
                .map(
                    networkService ->
                        buildDetectionReport(targetInfo, networkService, probingDetails))
                .collect(toImmutableList()))
        .build();
  }

  @Override
  public ImmutableList<Vulnerability> getAdvisories() {
    return ImmutableList.of(getAdvisory(AdditionalDetail.getDefaultInstance()));
  }

  Vulnerability getAdvisory(AdditionalDetail details) {
    return Vulnerability.newBuilder()
        .setMainId(
            VulnerabilityId.newBuilder()
                .setPublisher("GOOGLE")
                .setValue("REDIS_UNAUTHENTICATED_COMMAND_EXECUTION"))
        .setSeverity(Severity.HIGH)
        .setTitle("Redis unauthenticated command execution")
        .setDescription(VULN_DESCRIPTION)
        .setRecommendation(VULN_RECOMMENDATION)
        .addAdditionalDetails(details)
        .build();
  }

  private boolean isTransportProtocolTcp(NetworkService networkService) {
    return TransportProtocol.TCP.equals(networkService.getTransportProtocol());
  }

  private boolean isServiceVulnerable(
      NetworkService networkService, ProbingDetails probingDetails) {
    HostAndPort hp = NetworkEndpointUtils.toHostAndPort(networkService.getNetworkEndpoint());

    try (Socket socket = socketFactory.createSocket(hp.getHost(), hp.getPort())) {
      socket.getOutputStream().write("INFO server\r\n".getBytes(UTF_8));
      byte[] responseBuffer = new byte[100];
      int bytesRead = socket.getInputStream().read(responseBuffer, 0, responseBuffer.length);
      if (bytesRead <= 0) {
        logger.atWarning().log("%d bytes read (-1 means EOF) from redis service.", bytesRead);
        return false;
      }
      String response = new String(responseBuffer, 0, bytesRead, UTF_8);
      if ('-' == response.charAt(0)) {
        // '-' indicates Redis service error response
        // if authentication required, response is "-NOAUTH Authentication Required.\r\n"
        logger.atFinest().log("Redis service error response: %s...", response);
        return false;
      }
      if (response.matches("(?s).*\r\nredis_version:.*")) {
        // positive that it is Redis and that unauthenticated command was executed
        logger.atWarning().log("Redis service success response: %s...", response);
        probingDetails.response = response;
        return true;
      }
      // not sure it is Redis
      logger.atFinest().log("Likely not a Redis service response: %s...", response);
      return false;
    } catch (Exception e) {
      logger.atWarning().withCause(e).log("Unable to communicate with %s.", hp);
      return false;
    }
  }

  private DetectionReport buildDetectionReport(
      TargetInfo targetInfo,
      NetworkService vulnerableNetworkService,
      ProbingDetails probingDetails) {
    return DetectionReport.newBuilder()
        .setTargetInfo(targetInfo)
        .setNetworkService(vulnerableNetworkService)
        .setDetectionTimestamp(Timestamps.fromMillis(Instant.now(utcClock).toEpochMilli()))
        .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
        .setVulnerability(
            getAdvisory(
                AdditionalDetail.newBuilder()
                    .setDescription("response (first 100 bytes)")
                    .setTextData(TextData.newBuilder().setText(probingDetails.response))
                    .build()))
        .build();
  }
}
