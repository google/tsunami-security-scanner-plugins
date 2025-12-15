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

package com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.testers.keycloak;

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
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import javax.inject.Inject;

/** Credential tester specifically for keycloak. */
public final class KeycloakCredentialTester extends CredentialTester {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  private static final String KEYCLOAK_SERVICE = "keycloak";

  private final HttpClient httpClient;
  private boolean addCredentials = false;

  @Inject
  KeycloakCredentialTester(HttpClient httpClient) {
    this.httpClient = checkNotNull(httpClient);
  }

  @Override
  public String name() {
    return "KeycloakCredentialTester";
  }

  @Override
  public String description() {
    return "Keycloak credential tester.";
  }

  /**
   * Determines if this tester can accept the {@link NetworkService} based on the name of the
   * service or a custom fingerprint. The fingerprint is necessary since nmap doesn't always
   * recognize a Keycloak instance correctly.
   *
   * @param networkService the network service passed by tsunami
   * @return true if a Keycloak instance is recognized
   */
  @Override
  public boolean canAccept(NetworkService networkService) {
    boolean canAcceptByNmapReport =
        NetworkServiceUtils.getWebServiceName(networkService).equals(KEYCLOAK_SERVICE);

    if (canAcceptByNmapReport) {
      return true;
    }

    if (!NetworkServiceUtils.isWebService(networkService)) {
      return false;
    }

    return isKeycloakService(networkService);
  }

  /** Custom fingerprinting to detect Keycloak by checking for well-known endpoints. */
  private boolean isKeycloakService(NetworkService networkService) {
    String rootUrl = NetworkServiceUtils.buildWebApplicationRootUrl(networkService);

    // Check for Keycloak's OpenID Connect well-known configuration endpoint
    String[] fingerprintPaths = {
      "realms/master/.well-known/openid-configuration",
      "auth/realms/master/.well-known/openid-configuration"
    };

    for (String path : fingerprintPaths) {
      try {
        HttpResponse response =
            httpClient.send(get(rootUrl + path).withEmptyHeaders().build(), networkService);

        if (response.status().isSuccess() && response.bodyString().isPresent()) {
          String body = response.bodyString().get();
          // Check for Keycloak-specific markers in the OpenID configuration
          if (body.contains("issuer")
              && body.contains("authorization_endpoint")
              && body.contains("token_endpoint")
              && (body.contains("keycloak") || body.contains("/realms/"))) {
            logger.atInfo().log(
                "Detected Keycloak instance via custom fingerprinting at %s", rootUrl);
            addCredentials = true;
            return true;
          }
        }
      } catch (IOException e) {
        logger.atWarning().withCause(e).log(
            "Unable to fingerprint Keycloak at '%s'.", rootUrl + path);
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
      // Custom fingerprinting detected Keycloak (not Nmap), so credentials were fetched for
      // generic service type (e.g., "http"). Add Keycloak-specific default credentials.
      // TODO: remove this once fingerprinting is updated and made more robust

      // Default Keycloak usernames and passwords
      String[] defaultUsernames = {"admin", "username", "avery"};
      String[] defaultPasswords = {"admin", "password", "keycloak"};

      ImmutableList.Builder<TestCredential> keycloakDefaultsBuilder = ImmutableList.builder();
      for (String username : defaultUsernames) {
        for (String password : defaultPasswords) {
          keycloakDefaultsBuilder.add(
              TestCredential.create(username, java.util.Optional.of(password)));
        }
      }
      ImmutableList<TestCredential> keycloakDefaults = keycloakDefaultsBuilder.build();

      allCredentials =
          ImmutableList.<TestCredential>builder()
              .addAll(keycloakDefaults)
              .addAll(credentials)
              .build();

      logger.atInfo().log(
          "Custom fingerprinting detected Keycloak - testing %d credentials (%d defaults + %d provided)",
          allCredentials.size(), keycloakDefaults.size(), credentials.size());
    } else {
      // Nmap detected Keycloak, use credentials from providers only
      allCredentials = ImmutableList.copyOf(credentials);
    }

    // Always return 1st weak credential to gracefully handle no auth configured case
    return allCredentials.stream()
        .filter(cred -> isKeycloakAccessible(networkService, cred))
        .findFirst()
        .map(ImmutableList::of)
        .orElseGet(ImmutableList::of);
  }

  private boolean isKeycloakAccessible(NetworkService networkService, TestCredential credential) {
    String rootUrl = NetworkServiceUtils.buildWebApplicationRootUrl(networkService);

    // Keycloak token endpoints - try both old and new path formats
    String[] tokenPaths = {
      "realms/master/protocol/openid-connect/token",
      "auth/realms/master/protocol/openid-connect/token"
    };

    for (String tokenPath : tokenPaths) {
      String tokenUrl = rootUrl + tokenPath;

      try {
        // Keycloak uses OAuth2 Resource Owner Password Credentials Grant
        // Form data format: grant_type=password&client_id=admin-cli&username=X&password=Y
        String formData =
            String.format(
                "grant_type=password&client_id=admin-cli&username=%s&password=%s",
                URLEncoder.encode(credential.username(), StandardCharsets.UTF_8),
                URLEncoder.encode(credential.password().orElse(""), StandardCharsets.UTF_8));

        logger.atInfo().log(
            "Testing Keycloak credentials - URL: %s, Username: %s, FormData: %s",
            tokenUrl, credential.username(), formData);

        HttpResponse response =
            httpClient.send(
                post(tokenUrl)
                    .setHeaders(
                        HttpHeaders.builder()
                            .addHeader("Content-Type", "application/x-www-form-urlencoded")
                            .build())
                    .setRequestBody(ByteString.copyFromUtf8(formData))
                    .build(),
                networkService);

        // Successful authentication returns 200 with JSON containing access_token
        if (response.status() == HttpStatus.OK) {
          String body = response.bodyString().orElse("");
          if (body.contains("access_token")) {
            logger.atInfo().log(
                "Successfully authenticated to Keycloak with credentials: %s:%s",
                credential.username(), credential.password().orElse(""));
            return true;
          }
        } else {
          logger.atInfo().log(
              "Authentication failed - Status: %s, Response: %s",
              response.status().code(), response.bodyString().orElse("(empty response)"));
        }
      } catch (IOException e) {
        logger.atWarning().withCause(e).log("Unable to query '%s'.", tokenUrl);
        // Continue to try next path
      }
    }

    return false;
  }
}
