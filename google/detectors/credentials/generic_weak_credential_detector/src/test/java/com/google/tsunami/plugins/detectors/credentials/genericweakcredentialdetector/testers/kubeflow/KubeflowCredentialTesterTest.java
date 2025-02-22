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

package com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.testers.kubeflow;

import static com.google.common.truth.Truth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostnameAndPort;

import com.google.common.collect.ImmutableList;
import com.google.inject.Guice;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.provider.TestCredential;
import com.google.tsunami.proto.NetworkService;
import java.io.IOException;
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

/** Tests for {@link KubeflowCredentialTesterTest}. */
@RunWith(JUnit4.class)
public class KubeflowCredentialTesterTest {
  @Rule public MockitoRule rule = MockitoJUnit.rule();
  @Inject private KubeflowCredentialTester tester;
  private MockWebServer mockWebServer;
  private static final TestCredential WEAK_CRED_1 =
      TestCredential.create("user@example.com", Optional.of("12341234"));
  private static final TestCredential WRONG_CRED_1 =
      TestCredential.create("wrong", Optional.of("wrong"));

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
            .setServiceName("kubeflow")
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
            .setServiceName("kubeflow")
            .build();
    assertThat(tester.testValidCredentials(targetNetworkService, ImmutableList.of(WRONG_CRED_1)))
        .isEmpty();
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
            if (request.getPath().startsWith("/oauth2/start")
                && Objects.equals(request.getMethod(), "GET")) {
              return new MockResponse()
                  .setResponseCode(200)
                  .setHeader("set-cookie", "oauth2ProxyKubeflowCsrf")
                  .setHeader("location", "/location1");
            } else if (request.getPath().startsWith("/location1")
                && Objects.equals(request.getMethod(), "GET")) {
              return new MockResponse().setResponseCode(301).setHeader("location", "/location2");
            } else if (request.getPath().startsWith("/location2")
                && Objects.equals(request.getMethod(), "GET")) {
              return new MockResponse().setResponseCode(301).setHeader("location", "/location3");
            } else if (request.getPath().startsWith("/location3")
                && Objects.equals(request.getMethod(), "GET")) {
              return new MockResponse()
                  .setResponseCode(200)
                  .setBody(
                      "<!DOCTYPE html>\n"
                          + "<html>\n"
                          + "  <body class=\"theme-body\">\n"
                          + "<div class=\"theme-panel\">\n"
                          + "  <h2 class=\"theme-heading\">Log in to Your Account</h2>\n"
                          + "  <form method=\"post\""
                          + " action=\"/dex/auth/local/login?back=&amp;state=ncgzcbyfxo\">\n"
                          + "    <div class=\"theme-form-row\">\n"
                          + "      <div class=\"theme-form-label\">\n"
                          + "        <label for=\"userid\">Email Address</label>\n"
                          + "      </div>\n"
                          + "    </div>\n"
                          + "  </body>\n"
                          + "</html>");
            } else if (request.getPath().startsWith("/dex/auth/local/login?back=&state=")
                && Objects.equals(request.getMethod(), "POST")
                && request
                    .getBody()
                    .toString()
                    .contains("login=user%40example.com&password=12341234")) {
              return new MockResponse().setResponseCode(200).setHeader("location", "/location5");
            } else if (request.getPath().startsWith("/location5")
                && Objects.equals(request.getMethod(), "GET")) {
              return new MockResponse()
                  .setResponseCode(200)
                  .setHeader("location", "/")
                  .setHeader("set-cookie", "oauth2_proxy_kubeflow=D1EtyeQnMFozaaaa;");
            } else if (request.getPath().startsWith("/api/dashboard-links")
                && Objects.equals(request.getMethod(), "GET")
                && request
                    .getHeader("Cookie")
                    .contains("oauth2_proxy_kubeflow=D1EtyeQnMFozaaaa;")) {
              return new MockResponse()
                  .setResponseCode(200)
                  .setHeader("content-type", "application/json; charset=utf-8")
                  .setBody(
                      "{\n"
                          + "    \"menuLinks\": [\n"
                          + "        {\n"
                          + "            \"type\": \"item\"\n"
                          + "        }\n"
                          + "    ],\n"
                          + "    \"documentationItems\": [\n"
                          + "        {\n"
                          + "            \"text\": \"Kubeflow Website\"\n"
                          + "        }\n"
                          + "    ],\n"
                          + "    \"quickLinks\": [\n"
                          + "        {\n"
                          + "            \"desc\": \"Pipelines\""
                          + "        }\n"
                          + "    ]\n"
                          + "}");
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
