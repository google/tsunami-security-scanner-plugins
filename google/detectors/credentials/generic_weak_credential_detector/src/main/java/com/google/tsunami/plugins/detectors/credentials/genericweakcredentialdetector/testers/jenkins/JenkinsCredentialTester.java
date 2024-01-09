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
package com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.testers.jenkins;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.tsunami.common.net.http.HttpRequest.get;
import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.common.base.Strings;
import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
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
import org.jsoup.Jsoup;
import org.jsoup.select.Elements;

/** Credential tester specifically for jenkins. */
public final class JenkinsCredentialTester extends CredentialTester {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  private final HttpClient httpClient;

  private static final String JENKINS_SERVICE = "jenkins";

  @Inject
  JenkinsCredentialTester(HttpClient httpClient) {
    this.httpClient = checkNotNull(httpClient);
  }

  @Override
  public String name() {
    return "JenkinsCredentialTester";
  }

  @Override
  public String description() {
    return "Jenkins credential tester.";
  }

  @Override
  public boolean canAccept(NetworkService networkService) {
    return NetworkServiceUtils.getWebServiceName(networkService).equals(JENKINS_SERVICE);
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
        .filter(cred -> isJenkinsAccessible(networkService, cred))
        .findFirst()
        .map(ImmutableList::of)
        .orElseGet(ImmutableList::of);
  }

  private boolean isJenkinsAccessible(NetworkService networkService, TestCredential credential) {
    var uriAuthority = NetworkEndpointUtils.toUriAuthority(networkService.getNetworkEndpoint());
    var url = String.format("http://%s/", uriAuthority) + "view/all/newJob";
    try {
      logger.atInfo().log(
          "url: %s, username: %s, password: %s",
          url, credential.username(), credential.password().orElse(""));
      HttpResponse response = sendRequestWithCredentials(url, credential);
      return response.status().isSuccess()
          && response
              .bodyString()
              .map(JenkinsCredentialTester::bodyContainsCreateItemForm)
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
      return httpClient.send(get(url).withEmptyHeaders().build());
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

  private static boolean bodyContainsCreateItemForm(String responseBody) {
    // An unauthenticated Jenkins instance will show a HTML form with id createItem when user visits
    // the /view/all/newJob endpoint.
    Elements createItemForm = Jsoup.parse(responseBody).select("form#createItem");
    if (createItemForm.isEmpty()) {
      return false;
    } else {
      logger.atInfo().log(
          "Jenkins allows creating jobs as logged-in user, this will allow remote code execution!");
      return true;
    }
  }
}
