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

package com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.testers.mlflow;

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
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;

/** Tests for {@link MlFlowCredentialTester}. */
@RunWith(JUnit4.class)
public class MlFlowCredentialTesterTest {
  @Rule public MockitoRule rule = MockitoJUnit.rule();
  @Mock private ConnectionProviderInterface mockConnectionProvider;
  @Mock private Connection mockConnection;
  @Inject private MlFlowCredentialTester tester;
  private MockWebServer mockWebServer;
  private static final TestCredential WEAK_CRED_1 =
      TestCredential.create("admin", Optional.of("password"));
  private static final TestCredential WEAK_CRED_2 =
      TestCredential.create("username", Optional.of("password"));
  private static final TestCredential WRONG_CRED_1 =
      TestCredential.create("wrong", Optional.of("wrong"));

  // The base64 encoding of default authentication username:password pairs which the tester will
  // send these headers to our mock webserver
  private static final String WEAK_CRED_AUTH_1 = "basic dXNlcm5hbWU6cGFzc3dvcmQ=";
  private static final String WEAK_CRED_AUTH_2 = "basic YWRtaW46cGFzc3dvcmQ=";

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
            .setServiceName("mlflow")
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
            .setServiceName("mlflow")
            .build();

    assertThat(
            tester.testValidCredentials(
                targetNetworkService, ImmutableList.of(WEAK_CRED_1, WEAK_CRED_2)))
        .containsExactly(WEAK_CRED_1);
  }

  @Test
  public void detect_mlflowService_canAccept() throws Exception {
    startMockWebServer();
    NetworkService targetNetworkService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .setServiceName("mlflow")
            .build();

    assertThat(tester.canAccept(targetNetworkService)).isTrue();
  }

  @Test
  public void detect_weakCredentialsExistAndMlflowInForeignLanguage_returnsFirstWeakCredentials()
      throws Exception {
    startMockWebServer();
    NetworkService targetNetworkService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .setServiceName("mlflow")
            .build();

    assertThat(
            tester.testValidCredentials(
                targetNetworkService, ImmutableList.of(WEAK_CRED_1, WEAK_CRED_2)))
        .containsExactly(WEAK_CRED_1);
  }

  @Test
  public void detect_noWeakCredentials_returnsNoCredentials() throws Exception {
    startMockWebServer();
    NetworkService targetNetworkService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .setServiceName("mlflow")
            .build();
    assertThat(tester.testValidCredentials(targetNetworkService, ImmutableList.of(WRONG_CRED_1)))
        .isEmpty();
  }

  @Test
  public void detect_nonMlflowService_skips() throws Exception {
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
                      "You are not authenticated. "
                          + "Please see https://www.mlflow.org/docs/latest/auth/index.html"
                          + "#authenticating-to-mlflow "
                          + "on how to authenticate");

          @Override
          public MockResponse dispatch(RecordedRequest request) {
            String authorizationHeader = request.getHeaders().get("Authorization");
            if (authorizationHeader == null) {
              return unauthorizedResponse;
            }
            if (request.getPath().matches("/api/2.0/mlflow/users/get\\?.*")
                && Objects.equals(request.getMethod(), "GET")) {
              boolean isDefaultCredentials =
                  authorizationHeader.equals(WEAK_CRED_AUTH_1)
                      || authorizationHeader.equals(WEAK_CRED_AUTH_2);
              if (isDefaultCredentials) {
                return new MockResponse()
                    .setResponseCode(200)
                    .setBody(
                        "{\"user\":{\"experiment_permissions\":[],\"id\":1,\"is_admin\":true,"
                            + "\"registered_model_permissions\":[],"
                            + "\"username\":\"admin\"}}");
              } else {
                return unauthorizedResponse;
              }
            }
            return new MockResponse().setResponseCode(404);
          }
        };
    mockWebServer.setDispatcher(dispatcher);
    mockWebServer.start();
    mockWebServer.url("/");
  }
}
