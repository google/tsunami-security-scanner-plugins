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
import static com.google.common.truth.Truth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostnameAndPort;
import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.common.collect.ImmutableList;
import com.google.common.io.Resources;
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
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for {@link ActifioCredentialTester}. */
@RunWith(JUnit4.class)
public class ActifioCredentialTesterTest {
  @Inject private ActifioCredentialTester tester;
  private MockWebServer mockWebServer;

  private static final TestCredential WEAK_CRED_1 =
      TestCredential.create("admin", Optional.of("password"));
  private static final TestCredential WEAK_CRED_2 =
      TestCredential.create("user", Optional.of("1234"));
  private static final TestCredential FIRST_LOGIN_CRED =
      TestCredential.create("newuser", Optional.of("default"));
  private static final TestCredential WRONG_CRED =
      TestCredential.create("wrong", Optional.of("wrongpass"));

  private static final String WEAK_CRED_AUTH_1 = "Basic YWRtaW46cGFzc3dvcmQ="; // admin:password
  private static final String WEAK_CRED_AUTH_2 = "Basic dXNlcjoxMjM0"; // user:1234
  private static final String FIRST_LOGIN_AUTH = "Basic bmV3dXNlcjpkZWZhdWx0"; // newuser:default

  private static final ServiceContext.Builder actifioServiceContext =
      ServiceContext.newBuilder()
          .setWebServiceContext(
              WebServiceContext.newBuilder().setSoftware(Software.newBuilder().setName("actifio")));

  @Before
  public void setup() {
    mockWebServer = new MockWebServer();
    Guice.createInjector(new HttpClientModule.Builder().build()).injectMembers(this);
  }

  @After
  public void tearDown() throws IOException {
    mockWebServer.shutdown();
  }

  @Test
  public void detect_weakCredentialsExist_returnsWeakCredentials() throws Exception {
    String successResponse =
        Resources.toString(
            Resources.getResource(this.getClass(), "testdata/successfulSessionResponse.json"),
            UTF_8);
    startMockWebServer(new ActifioResponseDispatcher(successResponse, null, null));

    NetworkService targetNetworkService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .setServiceName("http")
            .setServiceContext(actifioServiceContext)
            .setSoftware(Software.newBuilder().setName("http"))
            .build();

    assertThat(tester.testValidCredentials(targetNetworkService, ImmutableList.of(WEAK_CRED_1)))
        .containsExactly(WEAK_CRED_1);
  }

  @Test
  public void detect_weakCredentialsExist_returnsFirstWeakCredential() throws Exception {
    String successResponse =
        Resources.toString(
            Resources.getResource(this.getClass(), "testdata/successfulSessionResponse.json"),
            UTF_8);
    startMockWebServer(new ActifioResponseDispatcher(successResponse, null, null));

    NetworkService targetNetworkService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .setServiceName("http")
            .setServiceContext(actifioServiceContext)
            .build();

    // Should return only the first valid credential to avoid account lockouts
    assertThat(
            tester.testValidCredentials(
                targetNetworkService, ImmutableList.of(WEAK_CRED_1, WEAK_CRED_2)))
        .containsExactly(WEAK_CRED_1);
  }

  @Test
  public void detect_noWeakCredentials_returnsNoCredentials() throws Exception {
    String successResponse =
        Resources.toString(
            Resources.getResource(this.getClass(), "testdata/successfulSessionResponse.json"),
            UTF_8);
    startMockWebServer(new ActifioResponseDispatcher(successResponse, null, null));

    NetworkService targetNetworkService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .setServiceName("http")
            .setServiceContext(actifioServiceContext)
            .build();

    assertThat(tester.testValidCredentials(targetNetworkService, ImmutableList.of(WRONG_CRED)))
        .isEmpty();
  }

  @Test
  public void detect_firstLogin_returnsCredentialsAsValid() throws Exception {
    String successResponse =
        Resources.toString(
            Resources.getResource(this.getClass(), "testdata/successfulSessionResponse.json"),
            UTF_8);
    String firstLoginResponse =
        Resources.toString(
            Resources.getResource(this.getClass(), "testdata/firstLoginResponse.json"), UTF_8);
    startMockWebServer(new ActifioResponseDispatcher(successResponse, firstLoginResponse, null));

    NetworkService targetNetworkService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .setServiceName("http")
            .setServiceContext(actifioServiceContext)
            .build();

    assertThat(
            tester.testValidCredentials(targetNetworkService, ImmutableList.of(FIRST_LOGIN_CRED)))
        .containsExactly(FIRST_LOGIN_CRED);
  }

  @Test
  public void detect_mixedCredentials_returnsFirstValidOne() throws Exception {
    String successResponse =
        Resources.toString(
            Resources.getResource(this.getClass(), "testdata/successfulSessionResponse.json"),
            UTF_8);
    String firstLoginResponse =
        Resources.toString(
            Resources.getResource(this.getClass(), "testdata/firstLoginResponse.json"), UTF_8);
    startMockWebServer(new ActifioResponseDispatcher(successResponse, firstLoginResponse, null));

    NetworkService targetNetworkService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .setServiceName("http")
            .setServiceContext(actifioServiceContext)
            .build();

    // Should return only the first valid credential (WEAK_CRED_1), skipping invalid and not testing
    // FIRST_LOGIN_CRED
    assertThat(
            tester.testValidCredentials(
                targetNetworkService, ImmutableList.of(WEAK_CRED_1, WRONG_CRED, FIRST_LOGIN_CRED)))
        .containsExactly(WEAK_CRED_1);
  }

  @Test
  public void name_always_returnsExpectedName() {
    assertThat(tester.name()).isEqualTo("ActifioCredentialTester");
  }

  @Test
  public void description_always_returnsExpectedDescription() {
    assertThat(tester.description()).isEqualTo("Actifio Global Manager credential tester.");
  }

  @Test
  public void batched_always_returnsFalse() {
    assertThat(tester.batched()).isFalse();
  }

  private void startMockWebServer(Dispatcher dispatcher) throws IOException {
    mockWebServer.setDispatcher(dispatcher);
    mockWebServer.start();
  }

  static final class ActifioResponseDispatcher extends Dispatcher {
    private final String successResponse;
    private final String firstLoginResponse;
    private final String unauthorizedResponse;

    ActifioResponseDispatcher(
        String successResponse, String firstLoginResponse, String unauthorizedResponse) {
      this.successResponse = checkNotNull(successResponse);
      this.firstLoginResponse = firstLoginResponse;
      this.unauthorizedResponse =
          unauthorizedResponse != null
              ? unauthorizedResponse
              : "{\"err_code\":10011}"; // Default unauthorized response
    }

    @Override
    public MockResponse dispatch(RecordedRequest recordedRequest) {
      String path = recordedRequest.getPath();
      String authHeader = recordedRequest.getHeader("Authorization");

      // Handle session endpoint
      if (path.contains("/actifio/session")) {
        if (authHeader == null) {
          return new MockResponse()
              .setResponseCode(HttpStatus.UNAUTHORIZED.code())
              .setHeader("WWW-Authenticate", "Actifio")
              .setBody(unauthorizedResponse);
        }

        // Check for valid credentials (200 OK)
        if (authHeader.equals(WEAK_CRED_AUTH_1) || authHeader.equals(WEAK_CRED_AUTH_2)) {
          return new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody(successResponse);
        }

        // Check for first login credentials (419 with err_code 10011)
        if (authHeader.equals(FIRST_LOGIN_AUTH) && firstLoginResponse != null) {
          return new MockResponse().setResponseCode(419).setBody(firstLoginResponse);
        }

        // Invalid credentials
        return new MockResponse()
            .setResponseCode(HttpStatus.UNAUTHORIZED.code())
            .setBody(unauthorizedResponse);
      }

      // Default response
      return new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.code());
    }
  }
}
