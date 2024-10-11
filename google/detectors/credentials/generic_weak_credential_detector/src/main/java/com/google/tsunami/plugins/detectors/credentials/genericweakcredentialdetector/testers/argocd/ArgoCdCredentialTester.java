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
package com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.testers.argocd;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.tsunami.common.net.http.HttpRequest.get;
import static com.google.tsunami.common.net.http.HttpRequest.post;
import static com.google.tsunami.common.net.http.HttpStatus.TEMPORARY_REDIRECT;
import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.common.base.Strings;
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
import com.google.tsunami.common.net.http.HttpRequest;
import com.google.tsunami.common.net.http.HttpResponse;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.provider.TestCredential;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.tester.CredentialTester;
import com.google.tsunami.proto.NetworkService;
import java.io.IOException;
import java.util.Base64;
import java.util.List;
import javax.inject.Inject;

import jdk.jfr.ContentType;
import org.jsoup.Jsoup;
import org.jsoup.select.Elements;

/** Credential tester specifically for argocd. */
public final class ArgoCdCredentialTester extends CredentialTester {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  private final HttpClient httpClient;

  private static final String ARGOCD_SERVICE = "argocd";

  @Inject
  ArgoCdCredentialTester(HttpClient httpClient) {
    this.httpClient = checkNotNull(httpClient);
  }

  @Override
  public String name() {
    return "ArgoCdCredentialTester";
  }

  @Override
  public String description() {
    return "ArgoCd credential tester.";
  }

  @Override
  public boolean canAccept(NetworkService networkService) {
    return NetworkServiceUtils.getWebServiceName(networkService).equals(ARGOCD_SERVICE);
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
        .filter(cred -> isArgoCdAccessible(networkService, cred))
        .findFirst()
        .map(ImmutableList::of)
        .orElseGet(ImmutableList::of);
  }

  private boolean isArgoCdAccessible(NetworkService networkService, TestCredential credential) {
    var uriAuthority = NetworkEndpointUtils.toUriAuthority(networkService.getNetworkEndpoint());
    var url = String.format("http://%s/%s", uriAuthority, "api/v1/session");
    try {
      logger.atInfo().log(
          "url: %s, username: %s, password: %s",
          url, credential.username(), credential.password().orElse(""));
      ByteString loginReqBody =
          ByteString.copyFromUtf8(
              String.format(
                  "{\"username\":\"%s\",\"password\":\"%s\"}",
                  credential.username(), credential.password().get()));
      HttpHeaders loginHeaders =
          HttpHeaders.builder().addHeader("Content-Type", "application/json").build();
      HttpResponse loginResponse =
          httpClient.send(post(url).setHeaders(loginHeaders).setRequestBody(loginReqBody).build());
      if (loginResponse.status() == TEMPORARY_REDIRECT) {
        url = String.format("https://%s/%s", uriAuthority, "api/v1/session");
        loginResponse =
            httpClient.send(
                post(url).setHeaders(loginHeaders).setRequestBody(loginReqBody).build());
      }
      return loginResponse.status().isSuccess()
          && loginResponse.bodyString().isPresent()
          && bodyContainsToken(loginResponse.bodyString().get());
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Unable to query '%s'.", url);
      return false;
    }
  }

  private static boolean bodyContainsToken(String responseBody) {
    try {
      return JsonParser.parseString(responseBody).getAsJsonObject().has("token");
    } catch (IllegalStateException | JsonSyntaxException e) {
      return false;
    }
  }
}
