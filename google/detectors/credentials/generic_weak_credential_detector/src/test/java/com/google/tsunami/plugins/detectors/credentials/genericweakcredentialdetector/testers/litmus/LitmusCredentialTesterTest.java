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

package com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.testers.litmus;

import static com.google.common.truth.Truth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostnameAndPort;

import com.google.common.collect.ImmutableList;
import com.google.inject.Guice;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.provider.TestCredential;
import com.google.tsunami.proto.NetworkService;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.Optional;
import javax.inject.Inject;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;

/** Tests for {@link LitmusCredentialTester}. */
@RunWith(JUnit4.class)
public class LitmusCredentialTesterTest {
  @Rule public MockitoRule rule = MockitoJUnit.rule();
  @Inject private LitmusCredentialTester tester;
  private MockWebServer mockWebServer;
  private static final TestCredential WEAK_CRED_1 =
      TestCredential.create("admin", Optional.of("litmus"));
  private static final TestCredential WRONG_CRED_1 =
      TestCredential.create("wrong", Optional.of("wrong"));

  // The default username and password for Litmus Chaos Center
  private static final String DEFAULT_USERNAME = "admin";
  private static final String DEFAULT_PASSWORD = "litmus";

  @Before
  public void setup() {
    mockWebServer = new MockWebServer();
    Guice.createInjector(new HttpClientModule.Builder().build()).injectMembers(this);
  }

  @Test
  public void detect_weakCredentialsExist_returnsFirstWeakCredentials() throws Exception {
    startMockWebServer();
    NetworkService targetNetworkService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .setServiceName("litmus")
            .build();

    assertThat(tester.testValidCredentials(targetNetworkService, ImmutableList.of(WEAK_CRED_1)))
        .containsExactly(WEAK_CRED_1);
  }

  @Test
  public void detect_noWeakCredentials_returnsNoCredentials() throws Exception {
    startMockWebServer();
    NetworkService targetNetworkService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .setServiceName("litmus")
            .build();
    assertThat(tester.testValidCredentials(targetNetworkService, ImmutableList.of(WRONG_CRED_1)))
        .isEmpty();
  }

  @Test
  public void detect_litmusService_canAccept() throws Exception {
    startMockWebServer();
    NetworkService targetNetworkService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .setServiceName("litmus")
            .build();

    assertThat(tester.canAccept(targetNetworkService)).isTrue();
  }

  private void startMockWebServer() throws IOException {
    final Dispatcher dispatcher =
        new Dispatcher() {
          final MockResponse invalidCredentialsResponse =
              new MockResponse()
                  .setResponseCode(200)
                  .setHeader("Content-Type", "application/json")
                  .setBody(
                      "{\"error\":\"invalid_credentials\","
                          + "\"errorDescription\":\"Invalid Credentials\"}");

          @Override
          public MockResponse dispatch(RecordedRequest request) {
            // Handle Litmus Chaos Center login endpoint
            if (request.getPath().startsWith("/auth/login")
                && Objects.equals(request.getMethod(), "POST")) {
              String body = request.getBody().readString(StandardCharsets.UTF_8);

              // Check if credentials match admin:litmus
              if (body.contains("\"username\":\"" + DEFAULT_USERNAME + "\"")
                  && body.contains("\"password\":\"" + DEFAULT_PASSWORD + "\"")) {
                // Return success response with access token
                return new MockResponse()
                    .setResponseCode(200)
                    .setHeader("Content-Type", "application/json")
                    .setBody(
                        "{\"accessToken\":\"eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3NjUzODQzNTMsInJvbGUiOiJhZG1pbiIsInVpZCI6ImFmYjFjOThmLWQwODctNDBmZC04ZDgwLWM3YTE1NTA2Mjk5MCIsInVzZXJuYW1lIjoiYWRtaW4ifQ.LtRyawFb3aCozqJoy0WDvMIOAlfZXdjiSnmuHKQCcbKC9b-7I70sBaQRJlCab47Wm-2wa_HWdtxpJHviSxk3NA\","
                            + "\"expiresIn\":86400,\"projectID\":\"\",\"projectRole\":\"Owner\","
                            + "\"type\":\"Bearer\"}");
              } else {
                // Return invalid credentials error
                return invalidCredentialsResponse;
              }
            }

            // Handle login page GET request for fingerprinting
            if (request.getPath().startsWith("/login")
                && Objects.equals(request.getMethod(), "GET")) {
              return new MockResponse()
                  .setResponseCode(200)
                  .setBody(
                      "<!DOCTYPE html>\n"
                          + "<html>\n"
                          + "  <head><title>Litmus Chaos Center</title></head>\n"
                          + "  <body>\n"
                          + "    <h1>Welcome to Litmus Chaos Center</h1>\n"
                          + "  </body>\n"
                          + "</html>");
            }

            // Default response for unmatched requests
            return new MockResponse().setResponseCode(404).setBody("Not Found");
          }
        };
    mockWebServer.setDispatcher(dispatcher);
    mockWebServer.start();
    mockWebServer.url("/");
  }
}
