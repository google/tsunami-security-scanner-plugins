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

package com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.testers.actifio;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.tsunami.common.net.http.HttpRequest.post;
import static java.nio.charset.StandardCharsets.UTF_8;

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
import java.io.IOException;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import javax.inject.Inject;

/** Credential tester specifically for Actifio Global Manager. */
public final class ActifioCredentialTester extends CredentialTester {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  private static final String ACTIFIO_SERVICE = "actifio";
  private static final String SESSION_ENDPOINT = "actifio/session";

  private final HttpClient httpClient;
  private boolean detectedByCustomFingerprint = false;

  @Inject
  ActifioCredentialTester(HttpClient httpClient) {
    this.httpClient = checkNotNull(httpClient);
  }

  @Override
  public String name() {
    return "ActifioCredentialTester";
  }

  @Override
  public String description() {
    return "Actifio Global Manager credential tester.";
  }

  /**
   * Determines if this tester can accept the {@link NetworkService} based on the name of the
   * service or a custom fingerprint. The fingerprint is necessary since nmap doesn't always
   * recognize an Actifio Global Manager instance correctly.
   *
   * @param networkService the network service passed by tsunami
   * @return true if an Actifio Global Manager instance is recognized
   */
  @Override
  public boolean canAccept(NetworkService networkService) {
    boolean canAcceptByNmapReport =
        NetworkServiceUtils.getWebServiceName(networkService).equals(ACTIFIO_SERVICE);

    if (canAcceptByNmapReport) {
      detectedByCustomFingerprint = false;
      return true;
    }

    if (!NetworkServiceUtils.isWebService(networkService)) {
      return false;
    }

    boolean detectedByFingerprint = isActifioService(networkService);
    if (detectedByFingerprint) {
      detectedByCustomFingerprint = true;
    }
    return detectedByFingerprint;
  }

  /**
   * Custom fingerprinting to detect Actifio Global Manager by checking for well-known endpoints.
   */
  private boolean isActifioService(NetworkService networkService) {
    String rootUrl = NetworkServiceUtils.buildWebApplicationRootUrl(networkService);

    // Try HTTPS first since Actifio typically uses HTTPS
    // Skip this for localhost/127.0.0.1 (used in tests)
    String sessionUrl = rootUrl + SESSION_ENDPOINT;
    if (sessionUrl.startsWith("http://")
        && !sessionUrl.contains("localhost")
        && !sessionUrl.contains("127.0.0.1")) {
      sessionUrl = sessionUrl.replace("http://", "https://");
    }

    try {
      // Check for Actifio Global Manager's session endpoint
      HttpResponse response =
          httpClient.send(
              post(sessionUrl)
                  .setHeaders(
                      HttpHeaders.builder().addHeader("Content-Type", "application/json").build())
                  .setRequestBody(ByteString.copyFromUtf8("{}"))
                  .build(),
              networkService);

      // Actifio should return 401 Unauthorized with WWW-Authenticate: Actifio header
      if (response.status() == HttpStatus.UNAUTHORIZED
          && response.headers().get("www-authenticate").isPresent()
          && response.headers().get("www-authenticate").get().contains("Actifio")) {
        logger.atInfo().log(
            "Detected Actifio Global Manager instance via custom fingerprinting at %s", sessionUrl);
        return true;
      }

      // Also check if error response contains Actifio-specific error code
      if (response.bodyString().isPresent()) {
        try {
          JsonObject body = JsonParser.parseString(response.bodyString().get()).getAsJsonObject();
          if (body.has("err_code")) {
            logger.atInfo().log(
                "Detected Actifio Global Manager instance via error code response at %s",
                sessionUrl);
            return true;
          }
        } catch (JsonSyntaxException e) {
          // Not JSON, not Actifio
        }
      }
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Unable to fingerprint Actifio at '%s'.", sessionUrl);
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

    if (detectedByCustomFingerprint) {
      // Custom fingerprinting detected Actifio (not Nmap), so credentials were fetched for
      // generic service type (e.g., "http"). Add Actifio-specific default credentials.

      allCredentials =
          ImmutableList.<TestCredential>builder()
              .add(TestCredential.create("admin", Optional.of("password")))
              .addAll(credentials)
              .build();

      logger.atInfo().log(
          "Custom fingerprinting detected Actifio Global Manager - testing %d credentials (1"
              + " default + %d provided)",
          allCredentials.size(), credentials.size());
    } else {
      // Nmap detected Actifio, use credentials from providers only
      allCredentials = ImmutableList.copyOf(credentials);
    }

    // Return first valid credential to avoid unnecessary requests and potential account lockouts
    return allCredentials.stream()
        .filter(cred -> isActifioAccessible(networkService, cred))
        .findFirst()
        .map(ImmutableList::of)
        .orElseGet(ImmutableList::of);
  }

  private boolean isActifioAccessible(NetworkService networkService, TestCredential credential) {
    String rootUrl = NetworkServiceUtils.buildWebApplicationRootUrl(networkService);
    String sessionUrl = rootUrl + SESSION_ENDPOINT;

    // If HTTP, try HTTPS instead since Actifio often redirects HTTP to HTTPS
    // and POST redirects don't always preserve the method/body
    // Skip this for localhost/127.0.0.1 (used in tests)
    if (sessionUrl.startsWith("http://")
        && !sessionUrl.contains("localhost")
        && !sessionUrl.contains("127.0.0.1")) {
      sessionUrl = sessionUrl.replace("http://", "https://");
      logger.atInfo().log("Converting HTTP to HTTPS for Actifio: %s", sessionUrl);
    }

    try {
      logger.atInfo().log(
          "Testing Actifio Global Manager credentials - URL: %s, Username: %s",
          sessionUrl, credential.username());

      HttpResponse response = sendSessionRequest(sessionUrl, credential, networkService);

      // Successful authentication returns 200 with JSON containing session_id
      if (response.status() == HttpStatus.OK) {
        return validateSuccessfulLogin(response, credential);
      }

      // Check for invalid credentials error (401 with error code 10011)
      if (response.status() == HttpStatus.UNAUTHORIZED) {
        String body = response.bodyString().orElse("");
        logger.atInfo().log(
            "Authentication failed - Invalid credentials for user: %s", credential.username());
        return false;
      }

      // For non-standard status codes like 419, HttpStatus.code() may return 0
      // Check if response body contains err_code 10011 which indicates first login
      // This is valid credentials requiring password change
      String body = response.bodyString().orElse("");
      if (!body.isEmpty()) {
        try {
          JsonObject jsonBody = JsonParser.parseString(body).getAsJsonObject();
          if (jsonBody.has("err_code") && jsonBody.get("err_code").getAsInt() == 10011) {
            // This could be either 419 (first login) or 401 (invalid credentials)
            // Since we already checked for 401 above, this must be 419
            logger.atInfo().log(
                "First login detected (err_code 10011) for user: %s - credentials are valid",
                credential.username());
            return true;
          }
        } catch (JsonSyntaxException e) {
          logger.atWarning().withCause(e).log("Failed to parse response body: %s", body);
        }
      }
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Unable to query '%s'.", sessionUrl);
    }

    return false;
  }

  private HttpResponse sendSessionRequest(
      String sessionUrl, TestCredential credential, NetworkService networkService)
      throws IOException {
    String authHeader =
        "Basic "
            + Base64.getEncoder()
                .encodeToString(
                    (credential.username() + ":" + credential.password().orElse(""))
                        .getBytes(UTF_8));

    String requestBody = "{}";

    var httpRequest =
        post(sessionUrl)
            .setHeaders(
                HttpHeaders.builder()
                    .addHeader("Content-Type", "application/json")
                    .addHeader("Authorization", authHeader)
                    .build())
            .setRequestBody(ByteString.copyFromUtf8(requestBody))
            .build();

    HttpResponse response = httpClient.send(httpRequest, networkService);

    return response;
  }

  private boolean validateSuccessfulLogin(HttpResponse response, TestCredential credential) {
    String body = response.bodyString().orElse("");
    try {
      JsonObject jsonBody = JsonParser.parseString(body).getAsJsonObject();
      if (jsonBody.has("session_id") && jsonBody.has("user")) {
        logger.atInfo().log(
            "Successfully authenticated to Actifio Global Manager with credentials: %s:%s",
            credential.username(), credential.password().orElse(""));
        return true;
      }
    } catch (JsonSyntaxException e) {
      logger.atWarning().withCause(e).log("Failed to parse success response body: %s", body);
    }
    return false;
  }
}
