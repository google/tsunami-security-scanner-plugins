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

package com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.testers.zenml;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.tsunami.common.net.http.HttpRequest.post;

import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;
import com.google.protobuf.ByteString;
import com.google.tsunami.common.data.NetworkEndpointUtils;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpHeaders;
import com.google.tsunami.common.net.http.HttpResponse;
import com.google.tsunami.common.net.http.HttpStatus;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.provider.TestCredential;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.tester.CredentialTester;
import com.google.tsunami.proto.NetworkService;
import java.io.IOException;
import java.util.List;
import javax.inject.Inject;

/** Credential tester specifically for zenml. */
public final class ZenMlCredentialTester extends CredentialTester {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  private static final String ZENML_SERVICE = "zenml";

  private final HttpClient httpClient;

  @Inject
  ZenMlCredentialTester(HttpClient httpClient) {
    this.httpClient = checkNotNull(httpClient);
  }

  @Override
  public String name() {
    return "ZenMlCredentialTester";
  }

  @Override
  public String description() {
    return "ZenMl credential tester.";
  }

  @Override
  public boolean canAccept(NetworkService networkService) {
    return NetworkServiceUtils.getWebServiceName(networkService).equals(ZENML_SERVICE);
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
        .filter(cred -> isZenMlAccessible(networkService, cred))
        .findFirst()
        .map(ImmutableList::of)
        .orElseGet(ImmutableList::of);
  }

  private boolean isZenMlAccessible(NetworkService networkService, TestCredential credential) {
    logger.atWarning().log(
        String.format(
            "username: %s password: %s", credential.username(), credential.password().orElse("")));
    var uriAuthority = NetworkEndpointUtils.toUriAuthority(networkService.getNetworkEndpoint());
    var loginApiUrl = String.format("http://%s/%s", uriAuthority, "api/v1/login");
    try {
      HttpResponse apiLoginResponse =
          httpClient.send(
              post(loginApiUrl)
                  .setHeaders(
                      HttpHeaders.builder()
                          .addHeader("Content-Type", "application/x-www-form-urlencoded")
                          .build())
                  .setRequestBody(
                      ByteString.copyFromUtf8(
                          String.format(
                              "username=%s&password=%s",
                              credential.username(), credential.password().orElse(""))))
                  .build());

      if (apiLoginResponse.status() == HttpStatus.UNAUTHORIZED
          && apiLoginResponse.bodyString().isPresent()
          && apiLoginResponse
              .bodyString()
              .get()
              .equals(
                  "{\"detail\":[\"AuthorizationException\","
                      + "\"Authentication error: invalid username or password\"]}")) {
        return false;
      }

      if (apiLoginResponse.status() == HttpStatus.OK
          && apiLoginResponse.bodyString().isPresent()
          && bodyContainsSuccessfulAccessToken(apiLoginResponse.bodyString().get())) {
        logger.atWarning().log("==============================================");
        return true;
      }

    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Unable to query '%s'.", loginApiUrl);
      return false;
    }
    return false;
  }

  /**
   * A successful authenticated request to the /api/v1/login endpoint returns a JSON with a root key
   * like the following: {"access_token":"An Access
   * Token","token_type":"bearer","expires_in":null,"refresh_token":null,"scope":null}
   */
  private static boolean bodyContainsSuccessfulAccessToken(String responseBody) {
    try {
      JsonObject response = JsonParser.parseString(responseBody).getAsJsonObject();

      if (response.has("access_token")
          && response.has("token_type")
          && response.has("refresh_token")
          && response.has("scope")
          && response.has("expires_in")) {
        logger.atInfo().log("Successfully logged in as a zenml user");
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
