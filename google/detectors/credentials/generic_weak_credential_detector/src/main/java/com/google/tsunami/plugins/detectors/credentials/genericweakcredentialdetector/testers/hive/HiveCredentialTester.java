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

package com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.testers.hive;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.tsunami.common.net.http.HttpRequest.get;

import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.common.net.HostAndPort;
import com.google.tsunami.common.data.NetworkEndpointUtils;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.db.ConnectionProviderInterface;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpResponse;
import com.google.tsunami.common.net.http.HttpStatus;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.provider.TestCredential;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.tester.CredentialTester;
import com.google.tsunami.proto.NetworkService;
import java.io.IOException;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.List;
import java.util.Optional;
import javax.inject.Inject;

/** Credential tester specifically for hive. */
public final class HiveCredentialTester extends CredentialTester {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  private final ConnectionProviderInterface connectionProvider;
  private final HttpClient httpClient;
  private static final String HIVE_TITLE = "<title>HiveServer2</title>";
  private static final int HIVE_TCP_PORT = 10000;

  @Inject
  HiveCredentialTester(ConnectionProviderInterface connectionProvider, HttpClient httpClient) {
    this.connectionProvider = checkNotNull(connectionProvider);
    this.httpClient = httpClient;
  }

  @Override
  public String name() {
    return "HiveCredentialTester";
  }

  @Override
  public String description() {
    return "Hive credential tester.";
  }

  @Override
  public boolean canAccept(NetworkService networkService) {
    String targetUri = NetworkServiceUtils.buildWebApplicationRootUrl(networkService);

    try {
      HttpResponse response = httpClient.send(get(targetUri).withEmptyHeaders().build(), networkService);
      if (response != null) {
        Optional<String> body = response.bodyString();
        if (response.status().code() == HttpStatus.OK.code()
                && body.isPresent() && body.get().contains(HIVE_TITLE)) {
          return true;
        }
      }
    } catch (IOException e) {
      return false;
    }
    return false;
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
        .filter(cred -> isHiveAccessible(networkService, cred))
        .collect(toImmutableList());
  }

  private boolean isHiveAccessible(NetworkService networkService, TestCredential credential) {
    HostAndPort targetPage = NetworkEndpointUtils.toHostAndPort(networkService.getNetworkEndpoint());
    try {
      String url = String.format("jdbc:hive2://%s:%d/default", targetPage.getHost(), HIVE_TCP_PORT);
      logger.atInfo().log(
          "url: %s, username: %s, password: %s",
          url, credential.username(), credential.password().orElse(""));
      Connection conn =
          connectionProvider.getConnection(
              url, credential.username(), credential.password().orElse(""));

      if (conn != null) {
        logger.atInfo().log("Connected to the Hive server successfully.");
        return true;
      }
    } catch (SQLException e) {
      logger.atSevere().log(
          "HiveCredentialTester sql error: %s (%d)", e.getMessage(), e.getErrorCode());
    }
    return false;
  }
}
