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

package com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.testers.tomcat;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.tsunami.common.net.http.HttpRequest.get;
import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.common.base.Ascii;
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
import org.jsoup.nodes.Document;

/** Credential tester for Tomcat. */
public final class TomcatHttpCredentialTester extends CredentialTester {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  private final HttpClient httpClient;

  private static final String TOMCAT_SERVICE = "tomcat";
  private static final String TOMCAT_PAGE_TITLE = "/manager";

  @Inject
  TomcatHttpCredentialTester(HttpClient httpClient) {
    this.httpClient = checkNotNull(httpClient).modify().setFollowRedirects(false).build();
  }

  @Override
  public String name() {
    return "TomcatHttpCredentialTester";
  }

  @Override
  public boolean batched() {
    return true;
  }

  @Override
  public String description() {
    return "Tomcat Http credential tester.";
  }

  @Override
  public boolean canAccept(NetworkService networkService) {

    var uriAuthority = NetworkEndpointUtils.toUriAuthority(networkService.getNetworkEndpoint());

    boolean canAcceptByNmapReport = 
        NetworkServiceUtils.getWebServiceName(networkService).equals(TOMCAT_SERVICE);

    if (canAcceptByNmapReport) {
      return true;
    }

    boolean canAcceptByCustomFingerprint = false;

    var url =
        String.format(
            "http://%s/%s",
            uriAuthority, "manager/");

    // Check if the server response indicates a redirection to /manager/html.
    // This typically means that the Tomcat Manager is active and automatically
    // redirects users to the management interface when accessing the base manager URL.
    try {
      logger.atInfo().log("probing Tomcat manager - custom fingerprint phase");

      HttpResponse response = httpClient.send(get(url).withEmptyHeaders().build());

      canAcceptByCustomFingerprint = response.status().code() == 302
      && response.headers().get("Location").get().equals("/manager/html");

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
        .filter(cred -> isTomcatAccessible(networkService, cred))
        .findFirst()
        .map(ImmutableList::of)
        .orElseGet(ImmutableList::of);
  }

  private boolean isTomcatAccessible(NetworkService networkService, TestCredential credential) {
    var uriAuthority = NetworkEndpointUtils.toUriAuthority(networkService.getNetworkEndpoint());
    var url =
        String.format(
            "http://%s/%s",
            uriAuthority, "manager/html");
    try {
      logger.atInfo().log(
          "url: %s, username: %s, password: %s",
          url, credential.username(), credential.password().orElse(""));
      HttpResponse response = sendRequestWithCredentials(url, credential);
      return response.status().isSuccess()
          && response
              .bodyString()
              .map(TomcatHttpCredentialTester::bodyContainsSuccessfulLoginElements)
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

  // This method checks if the response body contains elements indicative of a Tomcat manager page.
  // Specifically, it examines the page title rather than body elements because the content of the body can vary
  // depending on the language settings of the server. The title is less likely to change and provides a reliable
  // indicator of a successful login page.
  private static boolean bodyContainsSuccessfulLoginElements(String responseBody) {
    Document doc = Jsoup.parse(responseBody);
    String title = doc.title();

    if (Ascii.toLowerCase(title).contains(TOMCAT_PAGE_TITLE)) {
      logger.atInfo().log(
          "Found Tomcat endpoint (TOMCAT_PAGE_TITLE"
              + " string present in the page)");
      return true;
    } else {
      return false;
    }
  }

}
