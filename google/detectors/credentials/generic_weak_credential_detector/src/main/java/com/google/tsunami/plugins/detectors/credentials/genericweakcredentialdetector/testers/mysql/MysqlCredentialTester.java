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
package com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.testers.mysql;

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

/** Credential tester specifically for mysql. */
public final class MysqlCredentialTester extends CredentialTester {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  private final ConnectionProviderInterface connectionProvider;

  private static final ImmutableMap<String, TargetService> SERVICE_MAP =
      ImmutableMap.of("mysql", TargetService.MYSQL);

  @Inject
  MysqlCredentialTester(ConnectionProviderInterface connectionProvider) {
    this.connectionProvider = checkNotNull(connectionProvider);
  }

  @Override
  public String name() {
    return "MysqlCredentialTester";
  }

  @Override
  public String description() {
    return "Mysql credential tester.";
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
        .filter(cred -> isMysqlAccessible(networkService, cred))
        .collect(toImmutableList());
  }

  private boolean isMysqlAccessible(NetworkService networkService, TestCredential credential) {
    try {
      var url =
          String.format(
              "jdbc:mysql://%s/",
              NetworkEndpointUtils.toUriAuthority(networkService.getNetworkEndpoint()));
      logger.atInfo().log(
          "url: %s, username: %s, password: %s",
          url, credential.username(), credential.password().orElse(""));
      Connection conn =
          connectionProvider.getConnection(
              url, credential.username(), credential.password().orElse(""));

      if (conn != null) {
        logger.atInfo().log("Connected to the Mysql server successfully.");
        return true;
      }
    } catch (SQLException e) {
      logger.atSevere().log(
          "MysqlCredentialTester sql error: %s (%d)", e.getMessage(), e.getErrorCode());
    }
    return false;
  }
}
