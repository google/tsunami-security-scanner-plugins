/*
 * Copyright 2023 Google LLC
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
package com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.testers.postgres;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.flogger.GoogleLogger;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.db.ConnectionProviderInterface;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.proto.TargetService;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.provider.TestCredential;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.tester.CredentialTester;
import com.google.tsunami.proto.NetworkService;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.List;
import javax.inject.Inject;

/** Credential tester specifically for postgres. */
public final class PostgresCredentialTester extends CredentialTester {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  private final ConnectionProviderInterface connectionProvider;

  private static final ImmutableMap<String, TargetService> SERVICE_MAP =
      ImmutableMap.of("postgresql", TargetService.PSQL);

  @Inject
  PostgresCredentialTester(ConnectionProviderInterface connectionProvider) {
    this.connectionProvider = checkNotNull(connectionProvider);
  }

  @Override
  public String name() {
    return "PostgresCredentialTester";
  }

  @Override
  public String description() {
    return "Postgres credential tester.";
  }

  @Override
  public boolean canAccept(NetworkService networkService) {
    String serviceName = NetworkServiceUtils.getServiceName(networkService);
    return SERVICE_MAP.containsKey(serviceName);
  }

  @Override
  public ImmutableList<TestCredential> testValidCredentials(
      NetworkService networkService, List<TestCredential> credentials) {
    if (!canAccept(networkService)) {
      return ImmutableList.of();
    }

    return credentials.stream()
        .filter(cred -> isPostgresAccessible(networkService, cred))
        .collect(toImmutableList());
  }

  private boolean isPostgresAccessible(NetworkService networkService, TestCredential credential) {
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

    try {
      var url = String.format("jdbc:postgresql://%s:%d/postgres", host, port);
      logger.atInfo().log(
          "url: %s, username: %s, password: %s",
          url, credential.username(), credential.password().orElse(""));
      Connection conn =
          connectionProvider.getConnection(
              url, credential.username(), credential.password().orElse(""));

      if (conn != null) {
        logger.atInfo().log("Connected to the PostgreSQL server successfully.");
        return true;
      }
    } catch (SQLException e) {
      logger.atSevere().log(
          "PostgresCredentialTester sql error: %s (%d)", e.getMessage(), e.getErrorCode());
    }
    return false;
  }
}
