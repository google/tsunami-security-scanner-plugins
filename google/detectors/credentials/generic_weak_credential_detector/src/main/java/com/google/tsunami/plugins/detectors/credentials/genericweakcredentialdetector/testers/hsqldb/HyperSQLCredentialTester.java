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
package com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.testers.hsqldb;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.flogger.GoogleLogger;
import com.google.tsunami.common.data.NetworkEndpointUtils;
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

/** Credential tester specifically for HyperSQL. */
public final class HyperSQLCredentialTester extends CredentialTester {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  private final ConnectionProviderInterface connectionProvider;

  private static final ImmutableMap<String, TargetService> SERVICE_MAP =
      ImmutableMap.of("jdbc", TargetService.HSQLDB);

  @Inject
  HyperSQLCredentialTester(ConnectionProviderInterface connectionProvider) {
    this.connectionProvider = checkNotNull(connectionProvider);
  }

  @Override
  public String name() {
    return "HyperSQLCredentialTester";
  }

  @Override
  public String description() {
    return "HyperSQL credential tester.";
  }

  @Override
  public boolean canAccept(NetworkService networkService) {
    String serviceName = NetworkServiceUtils.getServiceName(networkService);
    return SERVICE_MAP.containsKey(serviceName);
  }

  @Override
  public boolean batched() {
    return true;
  }

  @Override
  public ImmutableList<TestCredential> testValidCredentials(
      NetworkService networkService, List<TestCredential> credentials) {
    if (!canAccept(networkService)) {
      return ImmutableList.of();
    }

    return credentials.stream()
        .filter(cred -> isHsqlAccessible(networkService, cred))
        .collect(toImmutableList());
  }

  /**
   * Using testdb as database name since hsqldb requires a database name in order to perform the
   * connection However hsqldb does not create a default database during installation testdb is the
   * database name used within the documentation
   */
  private boolean isHsqlAccessible(NetworkService networkService, TestCredential credential) {
    try {
      var url =
          String.format(
              "jdbc:hsqldb:hsql://%s/testdb",
              NetworkEndpointUtils.toUriAuthority(networkService.getNetworkEndpoint()));
      logger.atInfo().log(
          "url: %s, username: %s, password: %s",
          url, credential.username(), credential.password().orElse(""));
      Connection conn =
          connectionProvider.getConnection(
              url, credential.username(), credential.password().orElse(""));

      if (conn != null) {
        logger.atInfo().log("Connected to the Hyper SQL server successfully.");
        return true;
      }
    } catch (SQLException e) {
      logger.atSevere().log(
          "HyperSQLCredentialTester sql error: %s (%d)", e.getMessage(), e.getErrorCode());
    }
    return false;
  }
}
