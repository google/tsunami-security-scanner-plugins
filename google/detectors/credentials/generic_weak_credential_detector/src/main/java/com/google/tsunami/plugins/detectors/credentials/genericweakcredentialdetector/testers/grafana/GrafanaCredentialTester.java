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
package com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.testers.grafana;

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
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;

import javax.inject.Inject;
import java.io.IOException;
import java.util.Base64;
import java.util.List;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.tsunami.common.net.http.HttpRequest.get;
import static java.nio.charset.StandardCharsets.UTF_8;

/** Credential tester specifically for grafana. */
public final class GrafanaCredentialTester extends CredentialTester {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  private final HttpClient httpClient;

  private static final String GRAFANA_SERVICE =  "grafana";
  private static final String GRAFANA_PAGE_TITLE =  "grafana";

  @Inject
  GrafanaCredentialTester(HttpClient httpClient) {
    this.httpClient = checkNotNull(httpClient);
  }

  @Override
  public String name() {
    return "GrafanaCredentialTester";
  }

  @Override
  public String description() {
    return "Grafana credential tester.";
  }

  /**
   * Determines if this tester can accept the {@link NetworkService} based on the name of the service or a custom fingerprint.
   * The fingerprint is necessary since nmap doesn't recognize a grafana instance correctly.
   * @param networkService the network service passed by tsunami
   * @return true if a grafana instance is recognized
   */
  @Override
  public boolean canAccept(NetworkService networkService) {

    String uriAuthority = NetworkEndpointUtils.toUriAuthority(networkService.getNetworkEndpoint());

    boolean canAcceptByNmapReport = NetworkServiceUtils.getWebServiceName(networkService).equals(GRAFANA_SERVICE);
    boolean canAcceptByCustomFingerprint = false;

    var url = String.format("http://%s/", uriAuthority);
    try {
      logger.atInfo().log("probing Grafana home - custom fingerprint phase");

      HttpResponse response = httpClient.send(get(url).withEmptyHeaders().build());
      canAcceptByCustomFingerprint = response.status().isSuccess()
              && response
              .bodyString()
              .map(GrafanaCredentialTester::bodyContainsGrafanaElements)
              .orElse(false);
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Unable to query '%s'.", url);
      return false;
    }

    return canAcceptByNmapReport || canAcceptByCustomFingerprint;
  }

  // Checks if the response body contains elements of a grafana page - custom fingerprinting phase
  private static boolean bodyContainsGrafanaElements(String responseBody) {
    Document doc = Jsoup.parse(responseBody);
    String title = doc.title();

    if (title.toLowerCase().contains(GRAFANA_PAGE_TITLE)) {
      logger.atInfo().log("Grafana instance probably found");
      return true;
    } else {
      return false;
    }
  }


  // NOTE: grafana includes a login ratelimit by default in its config file https://github.com/grafana/grafana/blob/main/conf/defaults.ini as follows "disable_brute_force_login_protection = false"
  // The ratelimit will prevent the plugin from finding potential weak valid credentials.
  @Override
  public ImmutableList<TestCredential> testValidCredentials(
      NetworkService networkService, List<TestCredential> credentials) {

    return credentials.stream()
            .filter(cred -> isGrafanaAccessible(networkService, cred))
            .collect(toImmutableList());
  }



  private boolean isGrafanaAccessible(NetworkService networkService, TestCredential credential) {
    var uriAuthority = NetworkEndpointUtils.toUriAuthority(networkService.getNetworkEndpoint());
    var url = String.format("http://%s/", uriAuthority) + "dashboards";
    try {
      logger.atInfo().log(
              "url: %s, username: %s, password: %s",
              url, credential.username(), credential.password().orElse(""));
      HttpResponse response = sendRequestWithCredentials(url, credential);

      return response.status().isSuccess()
              && response
              .bodyString()
              .map(GrafanaCredentialTester::bodyContainsSuccessfulLoginElements)
              .orElse(false);
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Unable to query '%s'.", url);
      return false;
    }
  }

  private HttpResponse sendRequestWithCredentials(String url, TestCredential credential)
          throws IOException {

    var headers = HttpHeaders.builder()
            .addHeader(
                    "Authorization",
                    "Basic "
                            + Base64.getEncoder()
                            .encodeToString(
                                    (credential.username() + ":" + credential.password().orElse(""))
                                            .getBytes(UTF_8)))
            .build();

    return httpClient.send(get(url).setHeaders(headers).build());
  }

  //Check if the response contains elements in a page after a successful login via Basic Authentication
   private static boolean bodyContainsSuccessfulLoginElements(String responseBody) {

    // Calling the dashboard path with successful authentication will return a " window.grafanaBootData = {...}" json object
    // This method looks for the string "isSignedIn":true to check for access. In case of enabled anonymous access the response will contain "isSignedIn":false;
    // in case of a successful login via Basic Authentication the responseBody will contain "isSignedIn":true

    String successfulLoginInfo = "\"isSignedIn\":true";
    if (!responseBody.contains(successfulLoginInfo)) {
      return false;
    } else {
      logger.atInfo().log("Successful login in grafana");
      return true;
    }
  }

}

