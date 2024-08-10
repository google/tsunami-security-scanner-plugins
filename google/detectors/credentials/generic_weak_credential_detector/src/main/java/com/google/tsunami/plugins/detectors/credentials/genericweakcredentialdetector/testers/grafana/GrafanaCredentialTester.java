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

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.tsunami.common.net.http.HttpRequest.get;
import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.common.base.Ascii;
import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
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
import org.jsoup.nodes.Document;

/** Credential tester specifically for grafana. */
public final class GrafanaCredentialTester extends CredentialTester {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  private final HttpClient httpClient;

  private static final String GRAFANA_SERVICE = "grafana";
  private static final String GRAFANA_PAGE_TITLE = "grafana";
  private static final String GRAFANA_LOADING = "Loading Grafana";
  private static final String GRAFANA_BOOT_DATA = "window.grafanaBootData";

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

  private static String buildTargetUrl(NetworkService networkService, String path) {
    StringBuilder targetUrlBuilder = new StringBuilder();

    if (NetworkServiceUtils.isWebService(networkService)) {
      targetUrlBuilder.append(NetworkServiceUtils.buildWebApplicationRootUrl(networkService));

    } else {
      // Default to HTTP protocol when the scanner cannot identify the actual service.
      targetUrlBuilder
          .append("http://")
          .append(NetworkEndpointUtils.toUriAuthority(networkService.getNetworkEndpoint()))
          .append("/");
    }
    targetUrlBuilder.append(path);
    return targetUrlBuilder.toString();
  }

  /**
   * Determines if this tester can accept the {@link NetworkService} based on the name of the
   * service or a custom fingerprint. The fingerprint is necessary since nmap doesn't recognize a
   * grafana instance correctly.
   *
   * @param networkService the network service passed by tsunami
   * @return true if a grafana instance is recognized
   */
  @Override
  public boolean canAccept(NetworkService networkService) {

    boolean canAcceptByNmapReport =
        NetworkServiceUtils.getWebServiceName(networkService).equals(GRAFANA_SERVICE);

    if (canAcceptByNmapReport) {
      return true;
    }

    boolean canAcceptByCustomFingerprint = false;

    var url = buildTargetUrl(networkService, "");
    try {
      logger.atInfo().log("probing Grafana home - custom fingerprint phase");

      HttpResponse response = httpClient.send(get(url).withEmptyHeaders().build());

      // the endpoint /api/health is one of the available unauthenticated endpoint - see
      // https://grafana.com/docs/grafana/latest/developers/http_api/other/#health-api
      var healthApiUrl = buildTargetUrl(networkService, "api/health");
      HttpResponse apiHealthResponse =
          httpClient.send(get(healthApiUrl).withEmptyHeaders().build());

      canAcceptByCustomFingerprint =
          response.status().isSuccess()
              && response
                  .bodyString()
                  .map(GrafanaCredentialTester::bodyContainsGrafanaElements)
                  .orElse(false)
              && apiHealthResponse.status().isSuccess()
              && apiHealthResponse
                  .bodyString()
                  .map(GrafanaCredentialTester::bodyContainsHealthApiResponse)
                  .orElse(false);

    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Unable to query '%s'.", url);
      return false;
    }

    return canAcceptByCustomFingerprint;
  }

  @Override
  public boolean batched() {
    return true;
  }

  // Checks if the response body contains elements of a grafana page - custom fingerprinting phase
  private static boolean bodyContainsGrafanaElements(String responseBody) {
    Document doc = Jsoup.parse(responseBody);
    String title = doc.title();
    String body = doc.body().toString();

    if (Ascii.toLowerCase(title).contains(GRAFANA_PAGE_TITLE)
        && body.contains(GRAFANA_LOADING)
        && body.contains(GRAFANA_BOOT_DATA)) {
      logger.atInfo().log(
          "Found Grafana endpoint (GRAFANA_PAGE_TITLE, GRAFANA_LOADING, and GRAFANA_BOOT_DATA"
              + " strings present in the page)");
      return true;
    } else {
      return false;
    }
  }

  private static boolean bodyContainsHealthApiResponse(String responseBody) {
    try {
      JsonObject response = JsonParser.parseString(responseBody).getAsJsonObject();

      // The json response from the health endpoint is: {"commit": "81d85ce802", "database": "ok",
      // "version": "10.0.0"}

      if (response.has("commit") && response.has("database") && response.has("version")) {
        return true;
      } else {
        return false;
      }
    } catch (Exception e) {
      logger.atWarning().withCause(e).log(
          "An error occurred while parsing the json response: %s", responseBody);
      return false;
    }
  }

  // NOTE: grafana includes a login ratelimit by default in its config file
  // https://github.com/grafana/grafana/blob/main/conf/defaults.ini as follows
  // "disable_brute_force_login_protection = false"
  // The ratelimit will prevent the plugin from finding potential weak valid credentials.
  @Override
  public ImmutableList<TestCredential> testValidCredentials(
      NetworkService networkService, List<TestCredential> credentials) {

    return credentials.stream()
        .filter(cred -> isGrafanaAccessible(networkService, cred))
        .collect(toImmutableList());
  }

  private boolean isGrafanaAccessible(NetworkService networkService, TestCredential credential) {
    var url = buildTargetUrl(networkService, "api/user");
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

    var headers =
        HttpHeaders.builder()
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

  // Check if the response contains elements in a page after a successful login via Basic
  // Authentication
  private static boolean bodyContainsSuccessfulLoginElements(String responseBody) {

    try {
      JsonObject response = JsonParser.parseString(responseBody).getAsJsonObject();

      // A successful authenticated request to the /api/user endpoint returns a JSON
      // with at least the following keys:
      // {"id":1,"email":"admin@localhost","name":"","login":"admin","theme":"","orgId":1,"isGrafanaAdmin":true}
      if (response.has("id")
          && response.has("email")
          && response.has("login")
          && response.has("isGrafanaAdmin")) {
        logger.atInfo().log("Successfully logged in to Grafana");
        return true;
      } else {
        return false;
      }
    } catch (Exception e) {
      logger.atWarning().withCause(e).log(
          "An error occurred while parsing the json response: %s", responseBody);
      return false;
    }
  }
}
