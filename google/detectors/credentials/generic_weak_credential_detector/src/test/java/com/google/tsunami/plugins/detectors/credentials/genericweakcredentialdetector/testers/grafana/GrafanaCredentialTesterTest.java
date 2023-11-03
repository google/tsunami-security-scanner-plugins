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
package com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.testers.grafana;

import com.google.common.collect.ImmutableList;
import com.google.common.io.Resources;
import com.google.inject.Guice;
import com.google.tsunami.common.net.db.ConnectionProviderInterface;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.common.net.http.HttpStatus;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.provider.TestCredential;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.ServiceContext;
import com.google.tsunami.proto.Software;
import com.google.tsunami.proto.WebServiceContext;
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

import javax.inject.Inject;
import java.io.IOException;
import java.sql.Connection;
import java.util.Optional;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.truth.Truth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostnameAndPort;
import static java.nio.charset.StandardCharsets.UTF_8;


/** Tests for {@link GrafanaCredentialTester}. */
@RunWith(JUnit4.class)
public class GrafanaCredentialTesterTest {
  @Rule public MockitoRule rule = MockitoJUnit.rule();
  @Mock private ConnectionProviderInterface mockConnectionProvider;
  @Mock private Connection mockConnection;
  @Inject private GrafanaCredentialTester tester;
  private MockWebServer mockWebServer;
  private static final TestCredential WEAK_CRED_1 =
      TestCredential.create("user", Optional.of("1234"));
  private static final TestCredential WEAK_CRED_2 =
      TestCredential.create("root", Optional.of("pass"));
  private static final TestCredential WRONG_CRED_1 =
      TestCredential.create("wrong", Optional.of("pass"));

  private static final TestCredential EMPTY_CRED = TestCredential.create("", Optional.of(""));
  private static final String WEAK_CRED_AUTH_1 = "Authorization: Basic dXNlcjoxMjM0";
  private static final String WEAK_CRED_AUTH_2 = "Authorization: Basic cm9vdDpwYXNz";
  private static final ServiceContext.Builder grafanaServiceContext =
      ServiceContext.newBuilder()
          .setWebServiceContext(
              WebServiceContext.newBuilder().setSoftware(Software.newBuilder().setName("grafana")));

  @Before
  public void setup() {
    mockWebServer = new MockWebServer();
    Guice.createInjector(new HttpClientModule.Builder().build()).injectMembers(this);
  }

  @Test
  public void detect_weakCredentialsExists_returnsWeakCredentials() throws Exception {
    startMockWebServer(
        "/dashboards",
        200,
        Resources.toString(
            Resources.getResource(this.getClass(), "testdata/dashboardsPage.html"), UTF_8));
    NetworkService targetNetworkService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .setServiceName("http")
            .setServiceContext(grafanaServiceContext)
            .setSoftware(Software.newBuilder().setName("http"))
            .build();

    assertThat(tester.testValidCredentials(targetNetworkService, ImmutableList.of(WEAK_CRED_1)))
        .containsExactly(WEAK_CRED_1);
    mockWebServer.shutdown();
  }

  @Test
  public void detect_weakCredentialsExist_returnsAllWeakCredentials() throws Exception {
    startMockWebServer(
        "/dashboards",
        200,
        Resources.toString(
            Resources.getResource(this.getClass(), "testdata/dashboardsPage.html"), UTF_8));
    NetworkService targetNetworkService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .setServiceName("http")
            .setServiceContext(grafanaServiceContext)
            .build();

    assertThat(
            tester.testValidCredentials(
                targetNetworkService, ImmutableList.of(WEAK_CRED_1, WEAK_CRED_2)))
        .containsExactly(WEAK_CRED_1, WEAK_CRED_2);

    mockWebServer.shutdown();
  }


  @Test
  public void detect_noWeakCredentials_returnsNoCredentials() throws Exception {
    startMockWebServer("/dashboards", 200,
            Resources.toString(
                    Resources.getResource(this.getClass(), "testdata/dashboardsPage.html"), UTF_8)
    );
    NetworkService targetNetworkService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .setServiceName("http")
            .setServiceContext(grafanaServiceContext)
            .build();

    assertThat(tester.testValidCredentials(targetNetworkService, ImmutableList.of(WRONG_CRED_1)))
        .isEmpty();

    mockWebServer.shutdown();
  }



  private void startMockWebServer(String url, int responseCode, String response)
      throws IOException {
    mockWebServer.setDispatcher(new RespondWithDashboardsPageDispatcher(response));
    mockWebServer.start();
    mockWebServer.url(url);
  }

  static final class RespondWithDashboardsPageDispatcher extends Dispatcher {
    private final String dashboardsPage;

    RespondWithDashboardsPageDispatcher(String dashboardPageResponse) {
      this.dashboardsPage = checkNotNull(dashboardPageResponse);
    }

    @Override
    public MockResponse dispatch(RecordedRequest recordedRequest) {
      if (recordedRequest.getPath().startsWith("/dashboards")
          && (recordedRequest.getHeaders().toString().contains(WEAK_CRED_AUTH_1)
              || recordedRequest.getHeaders().toString().contains(WEAK_CRED_AUTH_2))
      ) {
        return new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody(dashboardsPage);
      }
      return new MockResponse().setResponseCode(HttpStatus.UNAUTHORIZED.code());
    }
  }
}


