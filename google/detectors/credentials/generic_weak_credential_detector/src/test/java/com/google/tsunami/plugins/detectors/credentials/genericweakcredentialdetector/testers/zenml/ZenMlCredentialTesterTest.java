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

package com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.testers.zenml;

import static com.google.common.truth.Truth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostnameAndPort;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.google.common.collect.ImmutableList;
import com.google.inject.Guice;
import com.google.tsunami.common.net.db.ConnectionProviderInterface;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.provider.TestCredential;
import com.google.tsunami.proto.NetworkService;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.util.Objects;
import java.util.Optional;
import javax.inject.Inject;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.Before;
import org.junit.Rule;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.junit.Test;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;
import org.mockito.Mock;

/** Tests for {@link ZenMlCredentialTester}. */
@RunWith(JUnit4.class)
public class ZenMlCredentialTesterTest {
  @Rule public MockitoRule rule = MockitoJUnit.rule();
  @Mock private ConnectionProviderInterface mockConnectionProvider;
  @Mock private Connection mockConnection;
  @Inject private ZenMlCredentialTester tester;
  private MockWebServer mockWebServer;
  private static final TestCredential WEAK_CRED_1 =
      TestCredential.create("default", Optional.of(""));
  private static final TestCredential WRONG_CRED_1 =
      TestCredential.create("wrong", Optional.of("wrong"));

  // the default username and password value for an insecure zenml instance
  private static final String DEFAULT_USERNAME = "default";
  private static final String DEFAULT_PASSWORD = "";

  @Before
  public void setup() {
    mockWebServer = new MockWebServer();
    Guice.createInjector(new HttpClientModule.Builder().build()).injectMembers(this);
  }

  @Test
  public void detect_weakCredentialsExists_returnsWeakCredentials() throws Exception {
    startMockWebServer();
    NetworkService targetNetworkService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .setServiceName("zenml")
            .build();

    assertThat(tester.testValidCredentials(targetNetworkService, ImmutableList.of(WEAK_CRED_1)))
        .containsExactly(WEAK_CRED_1);
    mockWebServer.shutdown();
  }

  @Test
  public void detect_weakCredentialsExist_returnsFirstWeakCredentials() throws Exception {
    startMockWebServer();
    NetworkService targetNetworkService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .setServiceName("zenml")
            .build();

    assertThat(tester.testValidCredentials(targetNetworkService, ImmutableList.of(WEAK_CRED_1)))
        .containsExactly(WEAK_CRED_1);
  }

  @Test
  public void detect_zenmlService_canAccept() throws Exception {
    startMockWebServer();
    NetworkService targetNetworkService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .setServiceName("zenml")
            .build();

    assertThat(tester.canAccept(targetNetworkService)).isTrue();
  }

  @Test
  public void detect_weakCredentialsExistAndZenmlInForeignLanguage_returnsFirstWeakCredentials()
      throws Exception {
    startMockWebServer();
    NetworkService targetNetworkService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .setServiceName("zenml")
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
            .setServiceName("zenml")
            .build();
    assertThat(tester.testValidCredentials(targetNetworkService, ImmutableList.of(WRONG_CRED_1)))
        .isEmpty();
  }

  @Test
  public void detect_nonZenmlService_skips() throws Exception {
    when(mockConnectionProvider.getConnection(any(), any(), any())).thenReturn(mockConnection);
    NetworkService targetNetworkService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(forHostnameAndPort("example.com", 8080))
            .setServiceName("http")
            .build();

    assertThat(tester.testValidCredentials(targetNetworkService, ImmutableList.of(WEAK_CRED_1)))
        .isEmpty();
    verifyNoInteractions(mockConnectionProvider);
  }

  private void startMockWebServer() throws IOException {
    final Dispatcher dispatcher =
        new Dispatcher() {
          final MockResponse unauthorizedResponse =
              new MockResponse()
                  .setResponseCode(401)
                  .setBody(
                      "{\"detail\":[\"AuthorizationException\","
                          + "\"Authentication error: invalid username or password\"]}");

          @Override
          public MockResponse dispatch(RecordedRequest request) {
            if (request.getPath().matches("/login") && Objects.equals(request.getMethod(), "GET")) {
              return new MockResponse()
                  .setResponseCode(200)
                  .setBody(" <title>ZenML Dashboard</title> ");
            }
            if (request.getPath().matches("/api/v1/login")
                && Objects.equals(request.getMethod(), "POST")
                && request
                    .getBody()
                    .readString(StandardCharsets.UTF_8)
                    .contains(
                        String.format(
                            "username=%s&password=%s", DEFAULT_USERNAME, DEFAULT_PASSWORD))) {
              return new MockResponse()
                  .setResponseCode(200)
                  .setBody(
                      "{\"access_token\":\"An AccessToken\",\"token_type\":\"bearer\","
                          + "\"expires_in\":null,\"refresh_token\":null,\"scope\":null}");
            } else {
              return unauthorizedResponse;
            }
          }
        };
    mockWebServer.setDispatcher(dispatcher);
    mockWebServer.start();
    mockWebServer.url("/");
  }
}
