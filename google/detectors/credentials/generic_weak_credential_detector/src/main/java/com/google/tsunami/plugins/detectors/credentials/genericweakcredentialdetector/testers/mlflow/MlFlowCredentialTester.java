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

package com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.testers.mlflow;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.tsunami.common.net.http.HttpRequest.get;
import static com.google.tsunami.common.net.http.HttpRequest.post;
import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.common.base.Strings;
import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;
import com.google.tsunami.common.data.NetworkEndpointUtils;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpHeaders;
import com.google.tsunami.common.net.http.HttpResponse;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.provider.TestCredential;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.tester.CredentialTester;
import com.google.tsunami.proto.NetworkService;
import java.io.IOException;
import java.util.Base64;
import java.util.List;
import javax.inject.Inject;

/** Credential tester specifically for mlflow. */
public final class MlFlowCredentialTester extends CredentialTester {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  private static final String MLFLOW_SERVICE = "mlflow";

  private final HttpClient httpClient;

  @Inject
  MlFlowCredentialTester(HttpClient httpClient) {
    this.httpClient = checkNotNull(httpClient);
  }

  @Override
  public String name() {
    return "MlFlowCredentialTester";
  }

  @Override
  public String description() {
    return "MlFlow credential tester.";
  }

  @Override
  public boolean canAccept(NetworkService networkService) {
    return NetworkServiceUtils.getWebServiceName(networkService).equals(MLFLOW_SERVICE);
  }

  @Override
  public boolean batched() {
    return true;
  }

  @Override
  public ImmutableList<TestCredential> testValidCredentials(
      NetworkService networkService, List<TestCredential> credentials) {
    // Always return 1st weak credential to gracefully handle no auth configured case, where we
    // return empty credential instead of all the weak credentials
    return credentials.stream()
        .filter(cred -> isMlFlowAccessible(networkService, cred))
        .findFirst()
        .map(ImmutableList::of)
        .orElseGet(ImmutableList::of);
  }

  private boolean isMlFlowAccessible(NetworkService networkService, TestCredential credential) {
    var uriAuthority = NetworkEndpointUtils.toUriAuthority(networkService.getNetworkEndpoint());
    var url =
        String.format(
            "http://%s/%s?username=%s",
            uriAuthority, "api/2.0/mlflow/users/get", credential.username());
    try {
      logger.atInfo().log(
          "url: %s, username: %s, password: %s",
          url, credential.username(), credential.password().orElse(""));
      HttpResponse response = sendRequestWithCredentials(url, credential);
      return response.status().isSuccess()
          && response
              .bodyString()
              .map(MlFlowCredentialTester::bodyContainsSuccessfulUserInfo)
              .orElse(false);
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Unable to query '%s'.", url);
      return false;
    }
  }

  private HttpResponse sendRequestWithCredentials(String url, TestCredential credential)
      throws IOException {
    // For testing no-auth configured case, no auth header is passed in
    if (Strings.isNullOrEmpty(credential.username())
        && Strings.isNullOrEmpty(credential.password().orElse(""))) {
      return httpClient.send(post(url).withEmptyHeaders().build());
    }

    return httpClient.send(
        get(url)
            .setHeaders(
                HttpHeaders.builder()
                    .addHeader(
                        "Authorization",
                        "basic "
                            + Base64.getEncoder()
                                .encodeToString(
                                    (credential.username() + ":" + credential.password().orElse(""))
                                        .getBytes(UTF_8)))
                    .build())
            .build());
  }

  /**
   * A successful authenticated request to the /api/2.0/mlflow/users/get?username=admin endpoint
   * returns a JSON with a root key like the following:
   * {"user":{"experiment_permissions":[],"id":1,"is_admin":true,"registered_model_permissions":[],
   * "username":"admin"}}
   */
  private static boolean bodyContainsSuccessfulUserInfo(String responseBody) {
    try {
      JsonObject response = JsonParser.parseString(responseBody).getAsJsonObject();

      if (response.has("user")) {
        logger.atInfo().log("Successfully received a mlflow user info");
        return true;
      } else {
        return false;
      }
    } catch (JsonSyntaxException e) {
      logger.atWarning().withCause(e).log(
          "An error occurred while parsing the json response: %s", responseBody);
      return false;
    }
  }
}
