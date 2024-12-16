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
package com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.testers.axis2;

import static com.google.common.base.Preconditions.checkNotNull;
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
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.Before;
import org.junit.Test;

/** Tests for {@link Axis2CredentialTester}. */
public class Axis2CredentialTesterTest {
  private static final TestCredential WEAK_CRED_1 =
      TestCredential.create("properUsername", Optional.of("properPassword"));
  private static final TestCredential WRONG_CRED_1 =
      TestCredential.create("wrong", Optional.of("pass"));

  @Inject private Axis2CredentialTester tester;
  private MockWebServer mockWebServer;

  private static final ServiceContext.Builder axis2ServiceContext =
      ServiceContext.newBuilder()
          .setWebServiceContext(
              WebServiceContext.newBuilder().setSoftware(Software.newBuilder().setName("axis2")));

  @Before
  public void setup() {
    mockWebServer = new MockWebServer();
    Guice.createInjector(new HttpClientModule.Builder().build()).injectMembers(this);
  }

  /**
   * No need for detect_weakCredentialsExist_returnsAllWeakCredentials since Axis2 only supports a
   * single administrator user
   */
  @Test
  public void detect_weakCredentialsExists_returnsWeakCredentials() throws Exception {
    startMockWebServer("/", 200, "<title>axis2 :: administration page</title>");
    NetworkService targetNetworkService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .setServiceName("http")
            .setServiceContext(axis2ServiceContext)
            .setSoftware(Software.newBuilder().setName("http"))
            .build();

    assertThat(tester.testValidCredentials(targetNetworkService, ImmutableList.of(WEAK_CRED_1)))
        .containsExactly(WEAK_CRED_1);
    mockWebServer.shutdown();
  }

  @Test
  public void detect_noWeakCredentials_returnsNoCredentials() throws Exception {
    startMockWebServer("/", 200, "<title>Login to Axis2 :: Administration page</title>");
    NetworkService targetNetworkService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .setServiceName("http")
            .setServiceContext(axis2ServiceContext)
            .setSoftware(Software.newBuilder().setName("http"))
            .build();

    assertThat(tester.testValidCredentials(targetNetworkService, ImmutableList.of(WRONG_CRED_1)))
        .isEmpty();
  }

  private void startMockWebServer(String url, int responseCode, String response)
      throws IOException {
    mockWebServer.enqueue(new MockResponse().setResponseCode(responseCode).setBody(response));
    mockWebServer.setDispatcher(new RespondUserInfoResponseDispatcher(response));
    mockWebServer.start();
    mockWebServer.url(url);
  }

  static final class RespondUserInfoResponseDispatcher extends Dispatcher {
    private final String loginPageResponse;

    RespondUserInfoResponseDispatcher(String loginPageResponse) {
      this.loginPageResponse = checkNotNull(loginPageResponse);
    }

    @Override
    public MockResponse dispatch(RecordedRequest recordedRequest) {
      var isLoginEndpoint = recordedRequest.getPath().startsWith("/axis2/axis2-admin/login");
      var hasWeakCred1 =
          recordedRequest
              .getBody()
              .readUtf8()
              .toString()
              .contains(
                  "userName="
                      + WEAK_CRED_1.username()
                      + "&password="
                      + WEAK_CRED_1.password().get());

      if (isLoginEndpoint && hasWeakCred1) {
        return new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody(loginPageResponse);
      }
      return new MockResponse().setResponseCode(HttpStatus.UNAUTHORIZED.code());
    }
  }
}
