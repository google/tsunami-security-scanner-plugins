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
import javax.net.SocketFactory;

/** Detects Redis unauthenticated command execution allowing RCE. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "RedisUnauthenticatedCommandExecutionDetector",
    version = "0.1",
    description = "Detects Redis unauthenticated command execution.",
    author = "Oleksii Prokopchuk (prokopchuk@google.com)",
    bootstrapModule = RedisUnauthenticatedCommandExecutionDetectorBootstrapModule.class)
@ForServiceName({"redis"})
public final class RedisUnauthenticatedCommandExecutionDetector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  static final String VULN_DESCRIPTION =
      "The scanner detected that this Redis instance does not require authentication.\n"
          + "This implies that anyone having network access to this Redis service can likely"
          + " execute any command, and may be able to escalate to the OS shell.\n"
          + "Unauthenticated command execution is a feature of Redis that can be desired if one is"
          + " positive that only trusted clients can ever access it over the network"
          + " (recommended).\n"
          + "\n"
          + "Details on the scanner logic:\n"
          + "The detection was made by successfully executing the Redis \"INFO server\" command"
          + " without authentication. The \"INFO\" command should normally require admin"
          + " privilege.\n"
          + "- A protected Redis instance would return \"-NOAUTH Authentication required.\".\n"
          + "- An unprotected Redis instance would successfully return, with the redis_version"
          + " field present in the response.";

  static final String VULN_RECOMMENDATION =
      "Preferably, make sure that only trusted clients can ever connect to Redis:"
          + " https://redis.io/topics/security.\n"
          + "Requesting authentication to execute Redis commands will protect it further. Edit"
          + " redis.conf: uncomment requirepass option and set a strong password. This file is"
          + " self-documented. General instructions: https://redis.io/topics/config.\n"
          + "If connections are over untrusted networks, they need to be encrypted (otherwise,"
          + " attacker may read passwords): https://redis.io/topics/encryption.\n"
          + "Then restart Redis service for the settings to take effect.";

  private final Clock utcClock;
  private final SocketFactory socketFactory;

  @Inject
  RedisUnauthenticatedCommandExecutionDetector(
      @UtcClock Clock utcClock, @SocketFactoryInstance SocketFactory socketFactory) {
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

  private boolean isTransportProtocolTcp(NetworkService networkService) {
    return TransportProtocol.TCP.equals(networkService.getTransportProtocol());
  }

  private boolean isServiceVulnerable(
      NetworkService networkService, ProbingDetails probingDetails) {
    HostAndPort hp = NetworkEndpointUtils.toHostAndPort(networkService.getNetworkEndpoint());

    try (Socket socket = socketFactory.createSocket(hp.getHost(), hp.getPort())) {
      socket.setSoTimeout(2000);
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
            Vulnerability.newBuilder()
                .setMainId(
                    VulnerabilityId.newBuilder()
                        .setPublisher("GOOGLE")
                        .setValue("REDIS_UNAUTHENTICATED_COMMAND_EXECUTION"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("Redis unauthenticated command execution")
                .setDescription(VULN_DESCRIPTION)
                .setRecommendation(VULN_RECOMMENDATION)
                .addAdditionalDetails(
                    AdditionalDetail.newBuilder()
                        .setDescription("response (first 100 bytes)")
                        .setTextData(TextData.newBuilder().setText(probingDetails.response))))
        .build();
  }
}
