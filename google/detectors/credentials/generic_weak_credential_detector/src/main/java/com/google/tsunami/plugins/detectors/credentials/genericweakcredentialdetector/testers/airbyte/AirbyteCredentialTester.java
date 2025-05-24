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

package com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.testers.airbyte;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.tsunami.common.net.http.HttpRequest.post;

import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
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

/** Credential tester specifically for airbyte. */
public final class AirbyteCredentialTester extends CredentialTester {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  private static final String AIRBYTE_SERVICE = "airbyte";

  private final HttpClient httpClient;

  @Inject
  AirbyteCredentialTester(HttpClient httpClient) {
    this.httpClient = checkNotNull(httpClient);
  }

  @Override
  public String name() {
    return "AirbyteCredentialTester";
  }

  @Override
  public String description() {
    return "Airbyte credential tester.";
  }

  @Override
  public boolean canAccept(NetworkService networkService) {
    return NetworkServiceUtils.getWebServiceName(networkService).equals(AIRBYTE_SERVICE);
  }

  @Override
  public boolean batched() {
    return false;
  }

  @Override
  public ImmutableList<TestCredential> testValidCredentials(
      NetworkService networkService, List<TestCredential> credentials) {
    // Always return 1st weak credential to gracefully handle no auth configured case, where we
    // return empty credential instead of all the weak credentials
    return credentials.stream()
        .filter(cred -> isAirbyteAccessible(networkService, cred))
        .findFirst()
        .map(ImmutableList::of)
        .orElseGet(ImmutableList::of);
  }

  private boolean isAirbyteAccessible(NetworkService networkService, TestCredential credential) {
    String rootUrl =
        "http://" + NetworkEndpointUtils.toUriAuthority(networkService.getNetworkEndpoint()) + "/";

    try {
      HttpResponse rootResponse =
          httpClient.send(
              post(rootUrl + "api/login")
                  .setHeaders(
                      HttpHeaders.builder().addHeader("content-type", "application/json").build())
                  .setRequestBody(
                      ByteString.copyFromUtf8(
                          String.format(
                              "{\"username\":\"%s\",\"password\":\"%s\"}",
                              credential.username(), credential.password().orElse(""))))
                  .build());

      if (rootResponse.status() == HttpStatus.OK
          && rootResponse.headers().get("set-cookie").isPresent()) {
        logger.atInfo().log(
            "Using default Airbyte credentials: %s:%s",
            credential.username(), credential.password().orElse(""));
        return true;
      }
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Unable to query '%s'.", rootUrl);
      return false;
    }
    return false;
  }
}
