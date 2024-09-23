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
package com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.testers.airflow;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.tsunami.common.net.http.HttpRequest.post;
import static com.google.tsunami.common.net.http.HttpRequest.get;

import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.protobuf.ByteString;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpHeaders;
import com.google.tsunami.common.net.http.HttpResponse;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.provider.TestCredential;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.tester.CredentialTester;
import com.google.tsunami.proto.NetworkService;
import java.io.IOException;
import java.net.HttpCookie;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.inject.Inject;

/** Credential tester specifically for airflow. */
public final class AirflowCredentialTester extends CredentialTester {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  private final HttpClient httpClient;

  private static final String AIRFLOW_SERVICE = "airflow";
  private static final Pattern CSRF_PATTERN =
      Pattern.compile("(var CSRF = |var csrfToken = )[\"']([\\w-.]+)[\"']");

  @Inject
  AirflowCredentialTester(HttpClient httpClient) {
    this.httpClient = checkNotNull(httpClient).modify().setFollowRedirects(false).build();
  }

  @Override
  public String name() {
    return "AirflowCredentialTester";
  }

  @Override
  public String description() {
    return "Airflow credential tester.";
  }

  @Override
  public boolean canAccept(NetworkService networkService) {
    return NetworkServiceUtils.getWebServiceName(networkService).equals(AIRFLOW_SERVICE);
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
        .filter(cred -> isAirflowAccessible(networkService, cred))
        .findFirst()
        .map(ImmutableList::of)
        .orElseGet(ImmutableList::of);
  }

  private boolean isAirflowAccessible(NetworkService networkService, TestCredential credential) {
    // sending the first request to retrieve a valid CSRF token and a valid session cookie
    Map<String, String> results = getFreshCsrfTokenAndSessionCookie(networkService);
    if (results == null) {
      return false;
    }
    String freshSessionCookieValue = results.get("freshSessionCookieValue");
    String freshCsrfToken = results.get("freshCsrfToken");

    String rootUrl = NetworkServiceUtils.buildWebApplicationRootUrl(networkService);
    String loginUrl = rootUrl + "login/";
    try {
      HttpResponse response =
          this.httpClient.send(
              post(loginUrl)
                  .setHeaders(
                      HttpHeaders.builder()
                          .addHeader("Content-Type", "application/x-www-form-urlencoded")
                          .addHeader("Cookie", String.format("session=%s", freshSessionCookieValue))
                          .build())
                  .setRequestBody(
                      ByteString.copyFrom(
                          String.format(
                              "csrf_token=%s&username=%s&password=%s",
                              freshCsrfToken,
                              credential.username(),
                              credential.password().orElse("")),
                          StandardCharsets.UTF_8))
                  .build(),
              networkService);
      return response.status().isRedirect()
          && response.headers().get("Location").isPresent()
          && response.headers().get("Location").get().equals("/home")
          && response.headers().get("Set-Cookie").isPresent()
          && response.headers().get("Set-Cookie").get().contains("session=");
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Unable to query '%s'.", loginUrl);
      return false;
    }
  }

  private Map<String, String> getFreshCsrfTokenAndSessionCookie(NetworkService networkService) {
    String rootUrl = NetworkServiceUtils.buildWebApplicationRootUrl(networkService);
    Map<String, String> results = new HashMap<>();

    HttpResponse firstResponse;
    try {
      firstResponse =
          this.httpClient.send(get(rootUrl + "login/").withEmptyHeaders().build(), networkService);
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Failed to send request.");
      return null;
    }

    if (firstResponse.bodyString().isEmpty()
        || firstResponse.headers().get("Set-Cookie").isEmpty()) {
      return null;
    }
    List<HttpCookie> parsedCookies =
        HttpCookie.parse(firstResponse.headers().get("Set-Cookie").get());
    String freshSessionCookieValue = null;
    for (HttpCookie cookie : parsedCookies) {
      if (cookie.getName().equals("session")) {
        freshSessionCookieValue = cookie.getValue();
      }
    }
    if (freshSessionCookieValue == null) {
      return null;
    }
    results.put("freshSessionCookieValue", freshSessionCookieValue);

    Matcher m = CSRF_PATTERN.matcher(firstResponse.bodyString().get());
    if (!m.find()) {
      return null;
    }
    String freshCsrfToken = m.group(2);
    results.put("freshCsrfToken", freshCsrfToken);
    return results;
  }
}
