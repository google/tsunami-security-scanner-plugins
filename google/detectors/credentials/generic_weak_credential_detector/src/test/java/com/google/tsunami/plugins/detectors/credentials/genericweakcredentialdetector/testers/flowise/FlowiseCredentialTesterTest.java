/*
 * Copyright 2026 Google LLC
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
package com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.testers.flowise;

import static com.google.common.truth.Truth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostnameAndPort;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.google.common.collect.ImmutableList;
import com.google.common.truth.IterableSubject;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;
import com.google.inject.Guice;
import com.google.tsunami.common.net.db.ConnectionProviderInterface;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.common.net.http.HttpStatus;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.provider.TestCredential;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.ServiceContext;
import com.google.tsunami.proto.Software;
import com.google.tsunami.proto.WebServiceContext;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.sql.Connection;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.function.Consumer;
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

/** Tests for {@link FlowiseCredentialTester}. */
@RunWith(JUnit4.class)
public class FlowiseCredentialTesterTest {
  @Rule public MockitoRule rule = MockitoJUnit.rule();
  @Mock private ConnectionProviderInterface mockConnectionProvider;
  @Mock private Connection mockConnection;
  @Inject private FlowiseCredentialTester tester;
  private MockWebServer mockWebServer;
  public static final TestCredential WEAK_CRED_1 =
      TestCredential.create("admin@localhost.lan", Optional.of("Password1!"));
  public static final TestCredential WEAK_CRED_2 =
      TestCredential.create("root@localhost.lan", Optional.of("Qwerty1!"));
  public static final TestCredential STRONG_CRED_1 =
      TestCredential.create("admin@localhost.lan", Optional.of("Ao7xGz378CzKxh7zZbOsFj10w."));
  public static final TestCredential STRONG_CRED_2 =
      TestCredential.create("test@localhost.lan", Optional.of("Ao7xGz378CzKxh7zZbOsFj10w."));
  private static final ServiceContext.Builder flowiseServiceContext =
      ServiceContext.newBuilder()
          .setWebServiceContext(
              WebServiceContext.newBuilder().setSoftware(Software.newBuilder().setName("flowise")));

  private static final String FLOWISE_LOG_FILE = null; // "/tmp/tsunamiFlowise.log";

  @Before
  public void setup() {
    mockWebServer = new MockWebServer();
    Guice.createInjector(new HttpClientModule.Builder().build()).injectMembers(this);
  }

  public void detect_global(
      ImmutableList<TestCredential> checkCreds, Consumer<IterableSubject> assertCondition)
      throws Exception {
    startMockWebServer();
    NetworkService targetNetworkService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .setServiceName("http")
            .setServiceContext(flowiseServiceContext)
            .setSoftware(Software.newBuilder().setName("http"))
            .build();

    assertCondition.accept(
        assertThat(tester.testValidCredentials(targetNetworkService, checkCreds)));

    mockWebServer.shutdown();
  }

  @Test
  public void detect_weakCredential_returnsWeakCredentials() throws Exception {
    detect_global(ImmutableList.of(WEAK_CRED_1), x -> x.containsExactly(WEAK_CRED_1));
  }

  @Test
  public void detect_weakCredential_returnsAllWeakCredentials() throws Exception {
    detect_global(
        ImmutableList.of(WEAK_CRED_1, WEAK_CRED_2),
        x -> x.containsExactly(WEAK_CRED_1, WEAK_CRED_2));
  }

  @Test
  public void detect_strongCredential_returnsNoCredentials() throws Exception {
    detect_global(ImmutableList.of(STRONG_CRED_1, STRONG_CRED_2), x -> x.isEmpty());
  }

  @Test
  public void detect_nonFlowiseService_skips() throws Exception {
    when(mockConnectionProvider.getConnection(any(), any(), any())).thenReturn(mockConnection);
    NetworkService targetNetworkService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(forHostnameAndPort("example.com", 8080))
            .setServiceName("http")
            .setServiceContext(
                ServiceContext.newBuilder()
                    .setWebServiceContext(
                        WebServiceContext.newBuilder()
                            .setSoftware(Software.newBuilder().setName("notFlowise"))))
            .build();

    assertThat(tester.testValidCredentials(targetNetworkService, ImmutableList.of(WEAK_CRED_1)))
        .isEmpty();
    verifyNoInteractions(mockConnectionProvider);
  }

  private void startMockWebServer() throws IOException {
    mockWebServer.setDispatcher(new FlowiseCredentialTesterDispatcher());
    mockWebServer.start();
  }

  private static final class FlowiseCredentialTesterDispatcher extends Dispatcher {
    private Set<TestCredential> appRegisteredCredentials = new HashSet<>();

    public FlowiseCredentialTesterDispatcher() {
      // Adding credentials to the list of valid users
      this.appRegisteredCredentials.add(FlowiseCredentialTesterTest.WEAK_CRED_1);
      this.appRegisteredCredentials.add(FlowiseCredentialTesterTest.WEAK_CRED_2);
    }

    @Override
    public MockResponse dispatch(RecordedRequest recordedRequest) {
      // Authentication API
      if (recordedRequest.getPath().equals("/api/v1/auth/login")) {
        // Expecting JSON-formatted body
        String reqBody = recordedRequest.getBody().readUtf8();
        try {
          JsonObject reqJson = JsonParser.parseString(reqBody).getAsJsonObject();

          // Only processing if expected parameters are set
          if (reqJson.has("email") && reqJson.has("password")) {

            String reqEmail = reqJson.get("email").getAsString();
            String reqPassword = reqJson.get("password").getAsString();

            writeToLog(
                "Received AUTH request: [email=" + reqEmail + " password=" + reqPassword + "]");

            for (TestCredential cred : this.appRegisteredCredentials) {
              // Existing account
              if (reqEmail.equals(cred.username())) {
                // Valid password
                if (reqPassword.equals(cred.password().orElse(""))) {
                  writeToLog("Response = OK");
                  return new MockResponse()
                      .setResponseCode(HttpStatus.OK.code())
                      .setBody(
                          "{\"id\":\"5b658172-fab9-478c-b6a3-bcf19a4ec1b3\",\"email\":\"admin@localhost.lan\",\"name\":\"Admin\",\"roleId\":\"6ec75515-d825-14ff-84a6-92e55c3f8991\",\"activeOrganizationId\":\"4ba1ad86-6cbb-4679-a86c-8b011dfc5e10\",\"activeOrganizationSubscriptionId\":null,\"activeOrganizationCustomerId\":null,\"activeOrganizationProductId\":\"\",\"isOrganizationAdmin\":true,\"activeWorkspaceId\":\"bf8816b0-9c49-4095-a646-0f26076c351e\",\"activeWorkspace\":\"Default"
                              + " Workspace\",\"assignedWorkspaces\":[{\"id\":\"bf8816b0-9c49-4095-a646-0f26076c351e\",\"name\":\"Default"
                              + " Workspace\",\"role\":\"owner\",\"organizationId\":\"4ba1ad86-6cbb-4679-a86c-8b011dfc5e10\"}],\"permissions\":[\"organization\",\"workspace\"],\"features\":{},\"isSSO\":false}");
                }
                // Wrong password
                else {
                  writeToLog("Response = 401");
                  return new MockResponse()
                      .setResponseCode(HttpStatus.UNAUTHORIZED.code())
                      .setBody(
                          "{\"statusCode\":401,\"success\":false,\"message\":\"Incorrect Email or"
                              + " Password\",\"stack\":{}}");
                }
              }
            }

            // Invalid account
            writeToLog("Response = 404");
            return new MockResponse()
                .setResponseCode(HttpStatus.NOT_FOUND.code())
                .setBody(
                    "{\"statusCode\":404,\"success\":false,\"message\":\"User Not"
                        + " Found\",\"stack\":{}}");
          }

        } catch (JsonSyntaxException e) {
          return new MockResponse().setResponseCode(HttpStatus.BAD_REQUEST.code());
        }
      }

      // Default response
      writeToLog("(unexpected) Default response");
      return new MockResponse().setResponseCode(HttpStatus.OK.code());
    }
  }

  private static boolean writeToLog(String str) {
    if (FLOWISE_LOG_FILE != null) {
      try (PrintWriter writer = new PrintWriter(new FileWriter(FLOWISE_LOG_FILE, true))) {
        writer.println(str);
      } catch (IOException e) {
        e.printStackTrace();
      }
    }
    return true;
  }
}
