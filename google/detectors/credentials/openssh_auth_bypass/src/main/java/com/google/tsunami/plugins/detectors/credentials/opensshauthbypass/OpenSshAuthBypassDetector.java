/*
 * Copyright 2026 Google LLC
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
package com.google.tsunami.plugins.detectors.credentials.opensshauthbypass;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Ascii;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.common.flogger.GoogleLogger;
import com.google.common.util.concurrent.Uninterruptibles;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.net.socket.TsunamiSocketFactory;
import com.google.tsunami.common.time.UtcClock;
import com.google.tsunami.plugin.PluginType;
import com.google.tsunami.plugin.VulnDetector;
import com.google.tsunami.plugin.annotations.ForServiceName;
import com.google.tsunami.plugin.annotations.PluginInfo;
import com.google.tsunami.plugins.detectors.credentials.opensshauthbypass.SshPasswordAuthClient.AuthAttemptResult;
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
import java.io.IOException;
import java.net.Socket;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import javax.inject.Inject;

/**
 * A {@link VulnDetector} that detects the OpenSSH password authentication bypass vulnerability on
 * musl-based systems (such as Alpine Linux).
 */
@ForServiceName({"ssh", "tcpwrapped"})
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "OpenSshAuthBypassDetector",
    version = "0.1",
    description =
        "Detects the OpenSSH password authentication bypass vulnerability on musl-based systems"
            + " (such as Alpine Linux).",
    author = "Tsunami Security Scanner",
    bootstrapModule = OpenSshAuthBypassDetectorBootstrapModule.class)
public final class OpenSshAuthBypassDetector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  @VisibleForTesting static final String VULNERABILITY_REPORT_PUBLISHER = "GOOGLE";

  @VisibleForTesting
  static final String VULNERABILITY_REPORT_ID = "OPENSSH_MUSL_PASSWORD_AUTH_BYPASS";

  @VisibleForTesting
  static final String VULNERABILITY_REPORT_TITLE =
      "OpenSSH Password Authentication Bypass on musl-based Systems";

  @VisibleForTesting
  static final String VULN_DESCRIPTION =
      "The OpenSSH server is vulnerable to a password authentication bypass when linked against"
          + " musl libc. When authenticating an account whose shadow password field is '*' (such as"
          + " the default root entry on Alpine Linux) and at least one other account on the system"
          + " has a modular crypt password hash (such as SHA-512), supplying a password longer than"
          + " 256 bytes causes musl's crypt() implementation to fail and return '*', matching the"
          + " locked shadow entry and granting unauthorized access.";

  @VisibleForTesting
  static final String RECOMMENDATION =
      "Upgrade OpenSSH to a patched version (such as openssh 9.9_p2-r1 or later on Alpine Linux),"
          + " or disable password authentication (PasswordAuthentication no) in sshd_config.";

  /**
   * Candidate usernames checked for {@code "*"} shadow entries. In Alpine Linux, {@code root} has
   * {@code "*"} in {@code /etc/shadow} by default; additional common account names cover targets
   * where {@code PermitRootLogin} is not set to {@code yes}. Kept concise so failed attempts stay
   * within OpenSSH 9.8+'s {@code PerSourcePenalties} threshold.
   */
  @VisibleForTesting
  static final ImmutableList<String> CANDIDATE_USERNAMES =
      ImmutableList.of("root", "alpine", "sshuser", "admin", "user", "guest");

  /**
   * Standard and fleet-observed alternative SSH ports accepted when Nmap labels the service as
   * {@code "tcpwrapped"} due to OpenSSH {@code PerSourcePenalties} or {@code MaxStartups}
   * rate-limiting during {@code -sV} banner fingerprinting.
   */
  @VisibleForTesting
  static final ImmutableSet<Integer> TCPWRAPPED_SSH_PORTS =
      ImmutableSet.of(22, 26, 222, 1022, 2022, 2222, 3389);

  /**
   * OpenSSH 9.8+ enables {@code PerSourcePenalties} by default ({@code noauth:1s, min:15s}). When
   * Tsunami's {@code NmapPortScanner} runs {@code -sV} and NSE scripts ({@code ssl-enum-ciphers},
   * {@code http-methods}, {@code ssl-cert}, {@code banner}), the ~18 unauthenticated probe
   * connections trigger a ~15-20s {@code PerSourcePenalties} cooldown window during which {@code
   * sshd} immediately closes new TCP connections before sending a banner. We retry on immediate
   * pre-banner EOF until the port-scan penalty window expires.
   */
  private static final int MAX_PENALTY_COOLDOWN_RETRIES = 10;

  private static final Duration PENALTY_COOLDOWN_SLEEP = Duration.ofSeconds(3);

  private final Clock utcClock;
  private final TsunamiSocketFactory socketFactory;
  private final SshPasswordAuthClient sshClient;

  @Inject
  OpenSshAuthBypassDetector(@UtcClock Clock utcClock, TsunamiSocketFactory socketFactory) {
    this.utcClock = checkNotNull(utcClock);
    this.socketFactory = checkNotNull(socketFactory);
    this.sshClient = new SshPasswordAuthClient();
  }

  @Override
  public ImmutableList<Vulnerability> getAdvisories() {
    return ImmutableList.of(
        Vulnerability.newBuilder()
            .setMainId(
                VulnerabilityId.newBuilder()
                    .setPublisher(VULNERABILITY_REPORT_PUBLISHER)
                    .setValue(VULNERABILITY_REPORT_ID))
            .addRelatedId(
                VulnerabilityId.newBuilder().setPublisher("CVE").setValue("CVE-2026-123158"))
            .setSeverity(Severity.CRITICAL)
            .setTitle(VULNERABILITY_REPORT_TITLE)
            .setDescription(VULN_DESCRIPTION)
            .setRecommendation(RECOMMENDATION)
            .build());
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("OpenSshAuthBypassDetector starts detecting.");

    return DetectionReportList.newBuilder()
        .addAllDetectionReports(
            matchedServices.stream()
                .filter(OpenSshAuthBypassDetector::isSshService)
                .map(service -> checkService(targetInfo, service))
                .flatMap(Optional::stream)
                .collect(toImmutableList()))
        .build();
  }

  private static boolean isSshService(NetworkService service) {
    if (service.getTransportProtocol() != TransportProtocol.TCP) {
      return false;
    }
    String serviceName = service.getServiceName();
    return serviceName.isEmpty()
        || Ascii.equalsIgnoreCase(serviceName, "ssh")
        || (Ascii.equalsIgnoreCase(serviceName, "tcpwrapped")
            && TCPWRAPPED_SSH_PORTS.contains(
                service.getNetworkEndpoint().getPort().getPortNumber()));
  }

  private Optional<DetectionReport> checkService(TargetInfo targetInfo, NetworkService service) {
    String host = service.getNetworkEndpoint().getIpAddress().getAddress();
    if (host.isEmpty()) {
      host = service.getNetworkEndpoint().getHostname().getName();
    }
    int port = service.getNetworkEndpoint().getPort().getPortNumber();

    for (String username : CANDIDATE_USERNAMES) {
      // Step 1: Probe with a 300-byte (>256) password first so a vulnerable account succeeds
      // without accumulating failed-connection PerSourcePenalties.
      AuthAttemptResult longPwResult =
          tryPasswordWithCooldownRetry(
              host, port, username, SshPasswordAuthClient.LONG_BYPASS_PASSWORD);
      switch (longPwResult) {
        case ACCEPTED:
          // Step 2: Verify with a second distinct 300-byte (>256) password to rule out the first
          // probe coincidentally matching an actual password.
          AuthAttemptResult secondLongPwResult =
              tryPasswordWithCooldownRetry(
                  host, port, username, SshPasswordAuthClient.SECOND_LONG_BYPASS_PASSWORD);
          if (secondLongPwResult != AuthAttemptResult.ACCEPTED) {
            break;
          }
          // Step 3 (Negative Control): Confirm that a short invalid password is REJECTED for the
          // same account, ruling out passwordless or accept-any-password configurations.
          AuthAttemptResult shortPwResult =
              tryPasswordWithCooldownRetry(
                  host, port, username, SshPasswordAuthClient.SHORT_INVALID_PASSWORD);
          if (shortPwResult == AuthAttemptResult.REJECTED) {
            logger.atInfo().log(
                "Verified OpenSSH password authentication bypass on %s:%d for user '%s'.",
                host, port, username);
            return Optional.of(buildDetectionReport(targetInfo, service, username));
          }
          break;
        case PASSWORD_AUTH_DISABLED:
        case NOT_OPENSSH:
        case CONNECTION_DROPPED:
          return Optional.empty();
        case REJECTED:
          break;
      }
    }
    return Optional.empty();
  }

  private AuthAttemptResult tryPasswordWithCooldownRetry(
      String host, int port, String username, String password) {
    for (int attempt = 0; attempt <= MAX_PENALTY_COOLDOWN_RETRIES; attempt++) {
      AuthAttemptResult result;
      try (Socket socket = socketFactory.createSocket(host, port)) {
        result = sshClient.tryPassword(socket, username, password);
      } catch (IOException e) {
        logger.atWarning().withCause(e).log(
            "Unable to connect to SSH service at %s:%d.", host, port);
        return AuthAttemptResult.NOT_OPENSSH;
      }
      if (result != AuthAttemptResult.CONNECTION_DROPPED) {
        return result;
      }
      if (attempt < MAX_PENALTY_COOLDOWN_RETRIES) {
        logger.atInfo().log(
            "SSH connection to %s:%d dropped before banner (likely OpenSSH PerSourcePenalties"
                + " cooldown after Nmap scan); retrying in %ds (attempt %d/%d)...",
            host,
            port,
            PENALTY_COOLDOWN_SLEEP.toSeconds(),
            attempt + 1,
            MAX_PENALTY_COOLDOWN_RETRIES);
        Uninterruptibles.sleepUninterruptibly(PENALTY_COOLDOWN_SLEEP);
      }
    }
    return AuthAttemptResult.CONNECTION_DROPPED;
  }

  private DetectionReport buildDetectionReport(
      TargetInfo targetInfo, NetworkService service, String verifiedUsername) {
    AdditionalDetail detail =
        AdditionalDetail.newBuilder()
            .setDescription(
                "Authentication bypass verified for locked account using >256-byte password")
            .setTextData(
                TextData.newBuilder()
                    .setText(
                        String.format(
                            "Successfully authenticated as \"%s\" with distinct %d-byte passwords"
                                + " while rejecting <=256-byte passwords.",
                            verifiedUsername, SshPasswordAuthClient.LONG_BYPASS_PASSWORD.length())))
            .build();
    return DetectionReport.newBuilder()
        .setTargetInfo(targetInfo)
        .setNetworkService(service)
        .setDetectionTimestamp(Timestamps.fromMillis(Instant.now(utcClock).toEpochMilli()))
        .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
        .setVulnerability(getAdvisories().get(0).toBuilder().addAdditionalDetails(detail).build())
        .build();
  }
}
