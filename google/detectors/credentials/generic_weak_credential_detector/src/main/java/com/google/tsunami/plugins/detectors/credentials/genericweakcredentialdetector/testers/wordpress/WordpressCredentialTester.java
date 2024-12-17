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
package com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.testers.wordpress;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.tsunami.common.net.http.HttpRequest.get;
import static com.google.tsunami.common.net.http.HttpRequest.post;
import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.common.net.HostAndPort;
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
import java.util.List;
import javax.inject.Inject;

/** Credential tester specifically for wordpress. */
public final class WordpressCredentialTester extends CredentialTester {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  private final HttpClient httpClient;

  private static final String WORDPRESS_SERVICE = "wordpress";
  @Inject
  WordpressCredentialTester(HttpClient httpClient) {
    this.httpClient = checkNotNull(httpClient);
  }

  @Override
  public String name() {
    return "WordpressCredentialTester";
  }

  @Override
  public String description() {
    return "Wordpress credential tester.";
  }

  @Override
  public boolean canAccept(NetworkService networkService) {
    return NetworkServiceUtils.getWebServiceName(networkService).equals(WORDPRESS_SERVICE);
  }

  @Override
  public boolean batched() {
    return true;
  }

  @Override
  public ImmutableList<TestCredential> testValidCredentials(
      NetworkService networkService, List<TestCredential> credentials) {
    return credentials.stream()
        .filter(cred -> isWordpressAccessible(networkService, cred))
        .collect(toImmutableList());
  }

  private boolean isWordpressAccessible(NetworkService networkService, TestCredential credential) {
    HostAndPort targetPage =
        NetworkEndpointUtils.toHostAndPort(networkService.getNetworkEndpoint());
    String host = targetPage.getHost();

    int port;
    if (targetPage.hasPort()) {
      port = targetPage.getPort();
    } else {
      logger.atWarning().log("Unexpected error; port shouldn't be empty, using default port (80)");
      port = 80;
    }


    var url = String.format("http://%s:%d/", host, port) + "wp-login.php";
    logger.atInfo().log(
        "url: %s, username: %s, password: %s",
        url, credential.username(), credential.password().orElse(""));
    String bodyParameters =
        "log="
            + credential.username()
            + "&pwd="
            + credential.password().get()
            + "&wp-submit=Log+In&redirect_to=http%3A%2F%2F"
            + host
            + "%3A"
            + port
            + "%2Fwp-admin%2F&testcookie=1";
    byte[] postData = bodyParameters.getBytes(UTF_8);

    try {
      HttpResponse response = wordpressPostRequest(url, host, port, postData);

      if (response.status().code() == 302) {
        return wordpressCheckAuth(response, host, port);
      }
      return false;
    } catch (IOException e) {
      // TODO: b/295948996 wordpress scanner has random connection issues
      logger.atWarning().withCause(e).log("Unable to query '%s'.", url);
      return false;
    }
  }

  HttpResponse wordpressPostRequest(String url, String host, int port, byte[] postData)
      throws IOException {
    return httpClient
        .modify()
        .setFollowRedirects(false)
        .build()
        .send(
            post(url)
                .setHeaders(
                    HttpHeaders.builder()
                        .addHeader("Host", host + ":" + port)
                        .addHeader(
                            "Accept",
                            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
                        .addHeader("Content-Type", "application/x-www-form-urlencoded")
                        .addHeader("Cookie", "wordpress_test_cookie=WP%20Cookie%20check;")
                        .addHeader("Connection", "close")
                        .build())
                .setRequestBody(ByteString.copyFrom(postData))
                .build());
  }

  boolean wordpressCheckAuth(HttpResponse response, String host, int port) throws IOException {
    if (!response.headers().getAll("Set-Cookie").isEmpty()) {
      response = httpClient.send(wordpressGetCookie(response, host, port));
      return (response.status().code() == 200
          && response.bodyBytes().get().toStringUtf8().contains("wp-admin-bar-new-content"));
    }
    return false;
  }

  HttpRequest wordpressGetCookie(HttpResponse response, String host, int port) {
    HttpHeaders.Builder cookieHeader = HttpHeaders.builder();
    String cookieParam = "";
    for (String element : response.headers().getAll("Set-Cookie")) {
      cookieParam += element.substring(0, element.indexOf(";")) + ";";
    }
    cookieHeader.addHeader("Cookie", cookieParam);
    return get(String.format("http://%s:%d/", host, port) + "wp-admin/")
            .setHeaders(cookieHeader.build())
            .build();
  }
}
