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

package com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.testers.litmus;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.tsunami.common.net.http.HttpRequest.get;
import static com.google.tsunami.common.net.http.HttpRequest.post;

import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.protobuf.ByteString;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpHeaders;
import com.google.tsunami.common.net.http.HttpResponse;
import com.google.tsunami.common.net.http.HttpStatus;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.provider.TestCredential;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.tester.CredentialTester;
import com.google.tsunami.proto.NetworkService;
import java.io.IOException;
import java.util.List;
import java.util.Optional;
import javax.inject.Inject;

/** Credential tester specifically for Litmus Chaos Center. */
public final class LitmusCredentialTester extends CredentialTester {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  private static final String LITMUS_SERVICE = "litmus";

  private final HttpClient httpClient;
  private boolean addCredentials = false;

  @Inject
  LitmusCredentialTester(HttpClient httpClient) {
    this.httpClient = checkNotNull(httpClient);
  }

  @Override
  public String name() {
    return "LitmusCredentialTester";
  }

  @Override
  public String description() {
    return "Litmus Chaos Center credential tester.";
  }

  /**
   * Determines if this tester can accept the {@link NetworkService} based on the name of the
   * service or a custom fingerprint. The fingerprint is necessary since nmap doesn't always
   * recognize a Litmus Chaos Center instance correctly.
   *
   * @param networkService the network service passed by tsunami
   * @return true if a Litmus Chaos Center instance is recognized
   */
  @Override
  public boolean canAccept(NetworkService networkService) {
    boolean canAcceptByNmapReport =
        NetworkServiceUtils.getWebServiceName(networkService).equals(LITMUS_SERVICE);

    if (canAcceptByNmapReport) {
      return true;
    }

    if (!NetworkServiceUtils.isWebService(networkService)) {
      return false;
    }

    return isLitmusService(networkService);
  }

  /** Custom fingerprinting to detect Litmus Chaos Center by checking for well-known endpoints. */
  private boolean isLitmusService(NetworkService networkService) {
    String rootUrl = NetworkServiceUtils.buildWebApplicationRootUrl(networkService);

    // Check for Litmus Chaos Center's login endpoint
    String[] fingerprintPaths = {"auth/login", "login"};

    for (String path : fingerprintPaths) {
      try {
        HttpResponse response =
            httpClient.send(get(rootUrl + path).withEmptyHeaders().build(), networkService);

        if (response.status().isSuccess() && response.bodyString().isPresent()) {
          String body = response.bodyString().get();
          // Check for Litmus-specific markers in the page
          if (body.contains("litmus") || body.contains("Litmus") || body.contains("chaos")) {
            logger.atInfo().log(
                "Detected Litmus Chaos Center instance via custom fingerprinting at %s", rootUrl);
            addCredentials = true;
            return true;
          }
        }
      } catch (IOException e) {
        logger.atWarning().withCause(e).log(
            "Unable to fingerprint Litmus at '%s'.", rootUrl + path);
      }
    }

    return false;
  }

  @Override
  public boolean batched() {
    return false;
  }

  @Override
  public ImmutableList<TestCredential> testValidCredentials(
      NetworkService networkService, List<TestCredential> credentials) {
    ImmutableList<TestCredential> allCredentials;

    if (addCredentials) {
      // Custom fingerprinting detected Litmus (not Nmap), so credentials were fetched for
      // generic service type (e.g., "http"). Add Litmus-specific default credentials.
      // TODO: remove this once fingerprinting is updated and made more robust

      allCredentials =
          ImmutableList.<TestCredential>builder()
              .add(TestCredential.create("admin", Optional.of("litmus")))
              .addAll(credentials)
              .build();

      logger.atInfo().log(
          "Custom fingerprinting detected Litmus Chaos Center - testing %d credentials (1 defaults"
              + " + %d provided)",
          allCredentials.size(), credentials.size());
    } else {
      // Nmap detected Litmus, use credentials from providers only
      allCredentials = ImmutableList.copyOf(credentials);
    }

    // Always return 1st weak credential to gracefully handle no auth configured case
    return allCredentials.stream()
        .filter(cred -> isLitmusAccessible(networkService, cred))
        .findFirst()
        .map(ImmutableList::of)
        .orElseGet(ImmutableList::of);
  }

  private boolean isLitmusAccessible(NetworkService networkService, TestCredential credential) {
    String rootUrl = NetworkServiceUtils.buildWebApplicationRootUrl(networkService);

    // Litmus Chaos Center auth endpoint
    String loginPath = "auth/login";
    String loginUrl = rootUrl + loginPath;

    try {
      // Litmus uses JSON authentication with username and password
      String jsonBody =
          String.format(
              "{\"username\":\"%s\",\"password\":\"%s\"}",
              credential.username(), credential.password().orElse(""));

      logger.atInfo().log(
          "Testing Litmus Chaos Center credentials - URL: %s, Username: %s",
          loginUrl, credential.username());

      HttpResponse response =
          httpClient.send(
              post(loginUrl)
                  .setHeaders(
                      HttpHeaders.builder()
                          .addHeader("Content-Type", "application/json")
                          .addHeader("Authorization", "Bearer null")
                          .build())
                  .setRequestBody(ByteString.copyFromUtf8(jsonBody))
                  .build(),
              networkService);

      // Successful authentication returns 200 with JSON containing accessToken
      if (response.status() == HttpStatus.OK) {
        String body = response.bodyString().orElse("");
        if (body.contains("accessToken")) {
          logger.atInfo().log(
              "Successfully authenticated to Litmus Chaos Center with credentials: %s:%s",
              credential.username(), credential.password().orElse(""));
          return true;
        }
      }

      // Check for invalid credentials error
      String body = response.bodyString().orElse("");
      if (body.contains("invalid_credentials")) {
        logger.atInfo().log(
            "Authentication failed - Invalid credentials for user: %s", credential.username());
      } else {
        logger.atInfo().log(
            "Authentication failed - Status: %s, Response: %s",
            response.status().code(), body.isEmpty() ? "(empty response)" : body);
      }
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Unable to query '%s'.", loginUrl);
    }

    return false;
  }
}
