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
package com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.testers.axis2;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.tsunami.common.net.http.HttpRequest.get;
import static com.google.tsunami.common.net.http.HttpRequest.post;

import com.google.common.base.Ascii;
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
import java.util.List;
import java.util.Optional;
import javax.inject.Inject;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;

/** Credential tester specifically for Apache Axis2 Administration Panel. */
public final class Axis2CredentialTester extends CredentialTester {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  private final HttpClient httpClient;

  private static final String AXIS_PAGE_TITLE = "axis 2 - home";
  private static final String AXIS_LOGIN_TITLE = "<title>axis2 :: administration page</title>";

  /**
   * Default credentials are inserted here instead of in the appropriate proto file since nmap
   * identifies the service name as "http". Due to this behavior, credentials have been inserted
   * here to not test such credentials against each "http" service.
   */
  private static final String AXIS_USERNAME = "admin";

  private static final String AXIS_PASSWORD = "axis2";

  @Inject
  Axis2CredentialTester(HttpClient httpClient) {
    this.httpClient = checkNotNull(httpClient);
  }

  @Override
  public String name() {
    return "Axis2CredentialTester";
  }

  @Override
  public String description() {
    return "Apache Axis2 Administration Panel credential tester.";
  }

  @Override
  public boolean batched() {
    return false;
  }

  /**
   * Determines if this tester can accept the {@link NetworkService} based on the name of the
   * service or a custom fingerprint. The fingerprint is necessary since nmap doesn't recognize a
   * Axis2 instance correctly.
   *
   * @param networkService the network service passed by tsunami
   * @return true if a axis2 instance is recognized
   */
  @Override
  public boolean canAccept(NetworkService networkService) {
    if (!NetworkServiceUtils.isWebService(networkService)) {
      return false;
    }
    String url = NetworkServiceUtils.buildWebApplicationRootUrl(networkService) + "axis2/";

    try {
      logger.atInfo().log("probing Axis2 Home Page - custom fingerprint phase");
      HttpResponse response = httpClient.send(get(url).withEmptyHeaders().build());

      return response.status().isSuccess()
          && response
              .bodyString()
              .map(Axis2CredentialTester::bodyContainsAxis2Elements)
              .orElse(false);
    } catch (Exception e) {
      logger.atWarning().withCause(e).log("Unable to query '%s'.", url);
      return false;
    }
  }

  /**
   * Checks if the response body contains elements of a axis2 home page - custom fingerprinting
   * phase
   */
  private static boolean bodyContainsAxis2Elements(String responseBody) {
    Document doc = Jsoup.parse(responseBody);
    String title = doc.title();

    return Ascii.toLowerCase(title).contains(AXIS_PAGE_TITLE);
  }

  private static boolean bodyContainsAxis2AdminElements(String responseBody) {
    // Checks if the response body contains title for successful authentication
    return Ascii.toLowerCase(responseBody).contains(AXIS_LOGIN_TITLE);
  }

  @Override
  public ImmutableList<TestCredential> testValidCredentials(
      NetworkService networkService, List<TestCredential> credentials) {

    // Added default credentials for Axis2 as reported within the documentation
    // https://axis.apache.org/axis2/java/core/docs/webadminguide.html#login
    TestCredential defaultUser = TestCredential.create(AXIS_USERNAME, Optional.of(AXIS_PASSWORD));
    if (isAxis2Accessible(networkService, defaultUser)) {
      return ImmutableList.of(defaultUser);
    }

    // Returning only first match since Axis2 supports a single user
    return credentials.stream()
        .filter(cred -> isAxis2Accessible(networkService, cred))
        .findFirst()
        .map(ImmutableList::of)
        .orElseGet(ImmutableList::of);
  }

  private boolean isAxis2Accessible(NetworkService networkService, TestCredential credential) {
    var url =
        NetworkServiceUtils.buildWebApplicationRootUrl(networkService) + "axis2/axis2-admin/login";
    try {
      logger.atInfo().log(
          "url: %s, username: %s, password: %s",
          url, credential.username(), credential.password().orElse(""));

      HttpResponse response = sendRequestWithCredentials(url, credential);

      return response.status().isSuccess()
          && response
              .bodyString()
              .map(Axis2CredentialTester::bodyContainsAxis2AdminElements)
              .orElse(false);
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Unable to query '%s'.", url);
      return false;
    }
  }

  /*
   * setFollowRedirects(true) in order to manage different behaviors of Axis2
   * Axis2 1.7.3 to 1.8.2 (latest) returns 302 to index when credentials are ok, to welcome otherwise
   * Axis2 before 1.7.3 returns 200 in both cases
   * All versions contain the same title after the redirect
   */
  private HttpResponse sendRequestWithCredentials(String url, TestCredential credential)
      throws IOException {
    return httpClient
        .modify()
        .setFollowRedirects(true)
        .build()
        .send(
            post(url)
                .setHeaders(
                    HttpHeaders.builder()
                        .addHeader("Content-Type", "application/x-www-form-urlencoded")
                        .build())
                .setRequestBody(
                    ByteString.copyFromUtf8(
                        String.format(
                            "userName=%s&password=%s",
                            credential.username(), credential.password().orElse(""))))
                .build());
  }
}
