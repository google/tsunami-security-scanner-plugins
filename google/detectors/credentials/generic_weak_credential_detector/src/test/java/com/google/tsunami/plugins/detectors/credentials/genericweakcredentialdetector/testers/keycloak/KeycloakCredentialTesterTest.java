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
package com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.testers.keycloak;

import static com.google.common.truth.Truth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostnameAndPort;

import com.google.common.collect.ImmutableList;
import com.google.inject.Guice;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.common.net.http.HttpStatus;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.provider.TestCredential;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.ServiceContext;
import com.google.tsunami.proto.Software;
import com.google.tsunami.proto.WebServiceContext;
import java.io.IOException;
import java.util.Optional;
import javax.inject.Inject;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for {@link KeycloakCredentialTester}. */
@RunWith(JUnit4.class)
public class KeycloakCredentialTesterTest {
  @Inject private KeycloakCredentialTester tester;
  private MockWebServer mockWebServer;

  private static final TestCredential WEAK_CRED_1 =
      TestCredential.create("admin", Optional.of("admin"));
  private static final TestCredential WEAK_CRED_2 =
      TestCredential.create("user", Optional.of("password"));
  private static final TestCredential WRONG_CRED_1 =
      TestCredential.create("wrong", Optional.of("wrongpass"));

  private static final String SUCCESS_TOKEN_RESPONSE =
      "{\"access_token\":\"eyJhbGc...\",\"expires_in\":300,\"refresh_token\":\"eyJhbGc...\","
          + "\"token_type\":\"Bearer\"}";

  private static final String ERROR_RESPONSE =
      "{\"error\":\"invalid_grant\",\"error_description\":\"Invalid user credentials\"}";

  private static final ServiceContext.Builder keycloakServiceContext =
      ServiceContext.newBuilder()
          .setWebServiceContext(
              WebServiceContext.newBuilder()
                  .setSoftware(Software.newBuilder().setName("keycloak")));

  @Before
  public void setup() {
    mockWebServer = new MockWebServer();
    Guice.createInjector(new HttpClientModule.Builder().build()).injectMembers(this);
  }

  @Test
  public void detect_weakCredentialsExists_returnsWeakCredentials() throws Exception {
    startKeycloakMockWebServer();
    NetworkService targetNetworkService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .setServiceName("http")
            .setServiceContext(keycloakServiceContext)
            .build();

    assertThat(tester.testValidCredentials(targetNetworkService, ImmutableList.of(WEAK_CRED_1)))
        .containsExactly(WEAK_CRED_1);
    mockWebServer.shutdown();
  }

  @Test
  public void detect_weakCredentialsExist_returnsFirstWeakCredential() throws Exception {
    startKeycloakMockWebServer();
    NetworkService targetNetworkService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .setServiceName("http")
            .setServiceContext(keycloakServiceContext)
            .build();

    assertThat(
            tester.testValidCredentials(
                targetNetworkService, ImmutableList.of(WEAK_CRED_1, WEAK_CRED_2)))
        .containsExactly(WEAK_CRED_1);
    mockWebServer.shutdown();
  }

  @Test
  public void detect_noWeakCredentials_returnsNoCredentials() throws Exception {
    startKeycloakMockWebServerRejectAll();
    NetworkService targetNetworkService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .setServiceName("http")
            .setServiceContext(keycloakServiceContext)
            .build();

    assertThat(tester.testValidCredentials(targetNetworkService, ImmutableList.of(WRONG_CRED_1)))
        .isEmpty();
    mockWebServer.shutdown();
  }

  @Test
  public void detect_nonKeycloakService_skips() throws Exception {
    NetworkService targetNetworkService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(forHostnameAndPort("example.com", 8080))
            .setServiceName("http")
            .setServiceContext(
                ServiceContext.newBuilder()
                    .setWebServiceContext(
                        WebServiceContext.newBuilder()
                            .setSoftware(Software.newBuilder().setName("notkeycloak"))))
            .build();

    assertThat(tester.testValidCredentials(targetNetworkService, ImmutableList.of(WEAK_CRED_1)))
        .isEmpty();
  }

  @Test
  public void detect_legacyKeycloakPath_returnsWeakCredentials() throws Exception {
    startKeycloakMockWebServer();
    NetworkService targetNetworkService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .setServiceName("http")
            .setServiceContext(keycloakServiceContext)
            .build();

    assertThat(tester.testValidCredentials(targetNetworkService, ImmutableList.of(WEAK_CRED_1)))
        .containsExactly(WEAK_CRED_1);
    mockWebServer.shutdown();
  }

  private void startKeycloakMockWebServer() throws IOException {
    mockWebServer.setDispatcher(
        new okhttp3.mockwebserver.Dispatcher() {
          @Override
          public MockResponse dispatch(RecordedRequest request) {
            String path = request.getPath();
            String body = request.getBody().readUtf8();

            // Handle both modern and legacy Keycloak paths
            if (path.contains("realms/master/protocol/openid-connect/token")
                || path.contains("auth/realms/master/protocol/openid-connect/token")) {

              // Check if credentials match
              if (body.contains("username=admin") && body.contains("password=admin")) {
                return new MockResponse()
                    .setResponseCode(HttpStatus.OK.code())
                    .setBody(SUCCESS_TOKEN_RESPONSE)
                    .addHeader("Content-Type", "application/json");
              } else if (body.contains("username=user") && body.contains("password=password")) {
                return new MockResponse()
                    .setResponseCode(HttpStatus.OK.code())
                    .setBody(SUCCESS_TOKEN_RESPONSE)
                    .addHeader("Content-Type", "application/json");
              } else {
                // Invalid credentials
                return new MockResponse()
                    .setResponseCode(HttpStatus.UNAUTHORIZED.code())
                    .setBody(ERROR_RESPONSE)
                    .addHeader("Content-Type", "application/json");
              }
            }

            return new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code());
          }
        });
    mockWebServer.start();
  }

  private void startKeycloakMockWebServerRejectAll() throws IOException {
    mockWebServer.setDispatcher(
        new okhttp3.mockwebserver.Dispatcher() {
          @Override
          public MockResponse dispatch(RecordedRequest request) {
            String path = request.getPath();

            // Handle both modern and legacy Keycloak paths
            if (path.contains("realms/master/protocol/openid-connect/token")
                || path.contains("auth/realms/master/protocol/openid-connect/token")) {
              // Reject ALL credentials for testing "no weak credentials" scenario
              return new MockResponse()
                  .setResponseCode(HttpStatus.UNAUTHORIZED.code())
                  .setBody(ERROR_RESPONSE)
                  .addHeader("Content-Type", "application/json");
            }

            return new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code());
          }
        });
    mockWebServer.start();
  }
}
