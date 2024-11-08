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

package com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.testers.kubeflow;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.tsunami.common.data.NetworkServiceUtils.buildWebApplicationRootUrl;
import static com.google.tsunami.common.net.http.HttpRequest.get;
import static com.google.tsunami.common.net.http.HttpRequest.post;

import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;
import com.google.protobuf.ByteString;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpHeaders;
import com.google.tsunami.common.net.http.HttpResponse;
import com.google.tsunami.common.net.http.HttpStatus;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.provider.TestCredential;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.tester.CredentialTester;
import com.google.tsunami.proto.NetworkService;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Objects;
import javax.inject.Inject;

/** Credential tester specifically for kubeflow. */
public final class KubeflowCredentialTester extends CredentialTester {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private final HttpClient httpClient;

  @Inject
  KubeflowCredentialTester(HttpClient httpClient) {
    this.httpClient =
        checkNotNull(httpClient, "HttpClient cannot be null.")
            .modify()
            .setFollowRedirects(false)
            .build();
  }

  @Override
  public String name() {
    return "KubeflowCredentialTester";
  }

  @Override
  public String description() {
    return "Kubeflow credential tester.";
  }

  @Override
  public boolean canAccept(NetworkService networkService) {
    return NetworkServiceUtils.isWebService(networkService);
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
        .filter(cred -> isKubeflowAccessible(networkService, cred))
        .findFirst()
        .map(ImmutableList::of)
        .orElseGet(ImmutableList::of);
  }

  private boolean isKubeflowAccessible(NetworkService networkService, TestCredential credential) {
    final String rootUri = buildWebApplicationRootUrl(networkService);
    //    logger.atWarning().log("======================= '%s'", credential.username());
    try {
      HttpResponse rsp =
          httpClient.send(
              get(rootUri + "oauth2/start?rd=%2F").withEmptyHeaders().build(), networkService);
      if (rsp.headers().get("set-cookie").isEmpty() || rsp.headers().get("location").isEmpty()) {
        return false;
      }
      String oauth2ProxyKubeflowCsrf = rsp.headers().get("set-cookie").get();
      HttpHeaders.Builder headers =
          HttpHeaders.builder().addHeader("Cookie", oauth2ProxyKubeflowCsrf);
      rsp =
          httpClient.send(
              get(rootUri + rsp.headers().get("location").get().substring(1))
                  .setHeaders(headers.build())
                  .build(),
              networkService);
      if (rsp.headers().get("location").isEmpty()) {
        return false;
      }
      rsp =
          httpClient.send(
              get(rootUri + rsp.headers().get("location").get().substring(1))
                  .setHeaders(headers.build())
                  .build(),
              networkService);
      if (rsp.headers().get("location").isEmpty()) {
        return false;
      }
      rsp =
          httpClient.send(
              get(rootUri + rsp.headers().get("location").get().substring(1))
                  .setHeaders(headers.build())
                  .build(),
              networkService);
      if (rsp.bodyString().isEmpty()) {
        return false;
      }
      String action = null;
      Document doc = Jsoup.parse(rsp.bodyString().get());
      for (Element anchor : doc.getElementsByTag("form")) {
        action = anchor.attr("action");
      }
      if (Objects.isNull(action)) {
        return false;
      }
      rsp =
          httpClient.send(
              post(rootUri + action.substring(1))
                  .setHeaders(
                      headers
                          .addHeader("Content-Type", "application/x-www-form-urlencoded")
                          .build())
                  .setRequestBody(
                      ByteString.copyFromUtf8(
                          String.format(
                              "login=%s&password=%s",
                              URLEncoder.encode(credential.username(), StandardCharsets.UTF_8),
                              URLEncoder.encode(
                                  credential.password().get(), StandardCharsets.UTF_8))))
                  .build(),
              networkService);
      if (rsp.headers().get("location").isEmpty()) {
        return false;
      }
      rsp =
          httpClient.send(
              get(rootUri + rsp.headers().get("location").get().substring(1))
                  .setHeaders(headers.build())
                  .build(),
              networkService);
      if (rsp.headers().get("set-cookie").isEmpty() || rsp.headers().get("location").isEmpty()) {
        return false;
      }
      String authCookie = "";
      ImmutableList<String> setCookieHeaders = rsp.headers().getAll("set-cookie");
      for (String setCookieHeader : setCookieHeaders) {
        if (setCookieHeader.startsWith("oauth2_proxy_kubeflow=")) {
          authCookie = setCookieHeader;
        }
      }
      rsp =
          httpClient.send(
              get(rootUri + "api/dashboard-links")
                  .setHeaders(
                      HttpHeaders.builder()
                          .addHeader("Cookie", authCookie)
                          .addHeader("Accept", "application/json")
                          .build())
                  .build(),
              networkService);
      if (rsp.bodyJson().isEmpty() || !rsp.status().isSuccess()) {
        return false;
      }
      JsonObject bodyJsonObj = rsp.bodyJson().get().getAsJsonObject();
      if (bodyJsonObj.has("menuLinks")
          || bodyJsonObj.has("documentationItems")
          || bodyJsonObj.has("quickLinks")) {
        return true;
      }
    } catch (RuntimeException | IOException e) {
      logger.atWarning().withCause(e).log("Failed to send HTTP request to '%s'", rootUri);
      return false;
    }
    return false;
  }
}
