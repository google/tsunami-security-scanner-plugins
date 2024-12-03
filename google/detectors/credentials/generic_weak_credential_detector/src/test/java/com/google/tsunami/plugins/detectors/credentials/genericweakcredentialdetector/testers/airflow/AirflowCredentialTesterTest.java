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

package com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.testers.airflow;

import static com.google.common.truth.Truth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostnameAndPort;
import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.common.collect.ImmutableList;
import com.google.inject.Guice;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.common.net.http.HttpStatus;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.provider.TestCredential;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.ServiceContext;
import com.google.tsunami.proto.Software;
import com.google.tsunami.proto.WebServiceContext;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Optional;
import javax.inject.Inject;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for {@link AirflowCredentialTester}. */
@RunWith(JUnit4.class)
public class AirflowCredentialTesterTest {
  @Inject private AirflowCredentialTester tester;
  private MockWebServer mockWebServer;
  private static final TestCredential WEAK_CRED_1 =
      TestCredential.create("airflow", Optional.of("airflow"));
  private static final TestCredential WRONG_CRED_1 =
      TestCredential.create("admin", Optional.of("admin"));
  private static final ServiceContext.Builder airflowServiceContext =
      ServiceContext.newBuilder()
          .setWebServiceContext(
              WebServiceContext.newBuilder().setSoftware(Software.newBuilder().setName("airflow")));

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
            .setServiceName("http")
            .setServiceContext(airflowServiceContext)
            .setSoftware(Software.newBuilder().setName("http"))
            .build();

    assertThat(tester.testValidCredentials(targetNetworkService, ImmutableList.of(WEAK_CRED_1)))
        .containsExactly(WEAK_CRED_1);
    mockWebServer.shutdown();
  }

  @Test
  public void detect_weakCredentialsExist_returnsAllWeakCredentials() throws Exception {
    startMockWebServer();
    NetworkService targetNetworkService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .setServiceName("http")
            .setServiceContext(airflowServiceContext)
            .build();

    assertThat(tester.testValidCredentials(targetNetworkService, ImmutableList.of(WEAK_CRED_1)))
        .containsExactly(WEAK_CRED_1);

    mockWebServer.shutdown();
  }

  @Test
  public void detect_noWeakCredentials_returnsNoCredentials() throws Exception {
    startMockWebServer();
    NetworkService targetNetworkService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .setServiceName("http")
            .setServiceContext(airflowServiceContext)
            .build();

    assertThat(tester.testValidCredentials(targetNetworkService, ImmutableList.of(WRONG_CRED_1)))
        .isEmpty();

    mockWebServer.shutdown();
  }

  private void startMockWebServer() throws IOException {
    mockWebServer.setDispatcher(new AirflowDispatcher());
    mockWebServer.start();
    mockWebServer.url("/");
  }

  static final class AirflowDispatcher extends Dispatcher {
    @Override
    public MockResponse dispatch(RecordedRequest recordedRequest) {

      if (recordedRequest.getPath().startsWith("/login/")
          && recordedRequest.getMethod().equals("POST")
          && recordedRequest.getHeader("Content-Type").equals("application/x-www-form-urlencoded")
          && recordedRequest.getHeader("Cookie").equals("session=aCookie")) {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        try {
          recordedRequest.getBody().writeTo(body);
        } catch (IOException e) {
          throw new RuntimeException(e);
        }
        if (body.toString(UTF_8).contains("csrf_token=a.CSRF.Token")
            && body.toString(UTF_8).contains("username=airflow")
            && body.toString(UTF_8).contains("password=airflow")) {
          return new MockResponse()
              .setResponseCode(302)
              .setHeader("Location", "/home")
              .setHeader("Set-Cookie", "session=someCookies");
        }
      } else if (recordedRequest.getPath().startsWith("/login/")
          && recordedRequest.getMethod().equals("GET")) {
        return new MockResponse()
            .setHeader("Set-Cookie", "session=aCookie")
            .setHeader("Content-Type", "application/x-www-form-urlencoded")
            .setBody("var csrfToken = 'a.CSRF.Token';");
      }
      return new MockResponse().setResponseCode(HttpStatus.UNAUTHORIZED.code());
    }
  }
}
