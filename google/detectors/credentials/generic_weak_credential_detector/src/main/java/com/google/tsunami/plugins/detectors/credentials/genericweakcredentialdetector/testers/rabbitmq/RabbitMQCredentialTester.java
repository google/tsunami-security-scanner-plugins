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

package com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.testers.rabbitmq;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.tsunami.common.net.http.HttpRequest.get;
import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;
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

/** Credential tester for RabbitMQ Management Portal. */
public final class RabbitMQCredentialTester extends CredentialTester {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  private final HttpClient httpClient;

  private static final String RABBITMQ_PAGE_TITLE = "RabbitMQ Management";
  private static final String RABBITMQ_SERVER_HEADER = "Cowboy";
  private static final String RABBITMQ_WWW_HEADER = "Basic realm=\"RabbitMQ Management\"";

  @Inject
  RabbitMQCredentialTester(HttpClient httpClient) {
    this.httpClient = checkNotNull(httpClient);
  }

  @Override
  public String name() {
    return "RabbitMQCredentialTester";
  }

  @Override
  public String description() {
    return "RabbitMQ credential tester.";
  }

  @Override
  public boolean batched() {
    return false;
  }

  private static String buildTargetUrl(NetworkService networkService, String path) {
    StringBuilder targetUrlBuilder = new StringBuilder();
    targetUrlBuilder.append(NetworkServiceUtils.buildWebApplicationRootUrl(networkService));
    targetUrlBuilder.append(path);
    return targetUrlBuilder.toString();
  }

  // Checks if the response body contains the title element of rabbitmq management page.
  // Custom fingerprint phase.
  private static boolean bodyContainsRabbitMqElements(String responseBody) {
    Document doc = Jsoup.parse(responseBody);
    String title = doc.title();

    if (title.contains(RABBITMQ_PAGE_TITLE)) {
      logger.atInfo().log(
          "Found RabbitMQ Management endpoint (RABBITMQ_PAGE_TITLE string present in the page)");
      return true;
    } else {
      return false;
    }
  }

  /**
   * Determines if this tester can accept the {@link NetworkService} based on the name of the
   * service or a custom fingerprint. The fingerprint is necessary since nmap doesn't recognize a
   * rabbitmq management instance correctly.
   *
   * @param networkService the network service passed by tsunami
   * @return true if a rabbitmq management instance is recognized
   */
  @Override
  public boolean canAccept(NetworkService networkService) {
    boolean isWebService = NetworkServiceUtils.isWebService(networkService);
    if (!isWebService) {
      return false;
    }
    boolean canAcceptByCustomFingerprint = false;

    String url = buildTargetUrl(networkService, "");
    try {
      logger.atInfo().log("Probing RabbitMQ Management Portal - custom fingerprint phase");
      HttpResponse response = httpClient.send(get(url).withEmptyHeaders().build());
      canAcceptByCustomFingerprint =
          response.status().isSuccess()
              && response.headers().get("server").isPresent()
              && response.headers().get("server").get().trim().equals(RABBITMQ_SERVER_HEADER)
              && response
                  .bodyString()
                  .map(RabbitMQCredentialTester::bodyContainsRabbitMqElements)
                  .orElse(false);
      url = buildTargetUrl(networkService, "api/overview");
      response = httpClient.send(get(url).withEmptyHeaders().build());
      canAcceptByCustomFingerprint =
          canAcceptByCustomFingerprint
              && response.headers().get("www-authenticate").isPresent()
              && response.headers().get("www-authenticate").get().equals(RABBITMQ_WWW_HEADER);
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Unable to query '%s'.", url);
      return false;
    }
    return canAcceptByCustomFingerprint;
  }

  @Override
  public ImmutableList<TestCredential> testValidCredentials(
      NetworkService networkService, List<TestCredential> credentials) {

    return credentials.stream()
        .filter(cred -> isCredentialValid(networkService, cred))
        .collect(toImmutableList());
  }

  private boolean isCredentialValid(NetworkService networkService, TestCredential credential) {
    var url = buildTargetUrl(networkService, "api/whoami");
    try {
      logger.atInfo().log(
          "url: %s, username: %s, password: %s",
          url, credential.username(), credential.password().orElse(""));
      HttpResponse response = sendRequestWithCredentials(url, credential);

      return response.status().isSuccess()
          && response
              .bodyString()
              .map(RabbitMQCredentialTester::bodyContainsSuccessfulLoginElements)
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

  /**
   * A successful authenticated request to the /api/whoami endpoint returns a JSON with at least the
   * following keys: {"name":"username","tags":["roles"]}
   */
  private static boolean bodyContainsSuccessfulLoginElements(String responseBody) {
    try {
      JsonObject response = JsonParser.parseString(responseBody).getAsJsonObject();

      if (response.has("name") && response.has("tags")) {
        logger.atInfo().log("Successfully logged in to RabbitMQ Management Portal");
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
