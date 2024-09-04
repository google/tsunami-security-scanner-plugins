/*
 * Copyright 2023 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.testers.tomcat;

import static com.google.common.truth.Truth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostnameAndPort;
import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.common.collect.ImmutableList;
import com.google.common.io.Resources;
import com.google.inject.Guice;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.provider.TestCredential;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.ServiceContext;
import com.google.tsunami.proto.Software;
import com.google.tsunami.proto.WebServiceContext;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import javax.inject.Inject;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for {@link TomcatAjpCredentialTester}. */
@RunWith(JUnit4.class)
public final class TomcatAjpCredentialTesterTest {

  @Inject private TomcatAjpCredentialTester tester;

  private static final TestCredential WEAK_CRED_1 =
      TestCredential.create("user", Optional.of("1234"));
  private static final TestCredential WEAK_CRED_2 =
      TestCredential.create("root", Optional.of("pass"));
  private static final TestCredential WRONG_CRED_1 =
      TestCredential.create("wrong", Optional.of("pass"));
  private static final String WEAK_CRED_AUTH_1 = "Basic dXNlcjoxMjM0";
  private static final String WEAK_CRED_AUTH_2 = "Basic cm9vdDpwYXNz";

  private AjpTestServer ajpTestServer;

  /**
  * Configure the Ajp Server before runing.
  *
  */
  @Before
  public void setup() throws IOException {
    ajpTestServer = new AjpTestServer();
    ajpTestServer.start();
    Guice.createInjector().injectMembers(this);
  }

  @Test
  public void detect_weakCredentialsExists_returnsWeakCredentials() throws Exception {
    ajpTestServer.setResponseForCredential(
        WEAK_CRED_AUTH_1,
        Resources.toByteArray(
            Resources.getResource(this.getClass(), "testdata/successfulAuthdResponse.bin")));

    NetworkService targetNetworkService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(ajpTestServer.getHost(), ajpTestServer.getPort()))
            .setServiceName("ajp13")
            .setServiceContext(
                ServiceContext.newBuilder()
                    .setWebServiceContext(
                        WebServiceContext.newBuilder()
                            .setSoftware(Software.newBuilder().setName("tomcat"))))
            .build();

    assertThat(tester.testValidCredentials(targetNetworkService, ImmutableList.of(WEAK_CRED_1)))
        .containsExactly(WEAK_CRED_1);
    ajpTestServer.stop();
  }

  @Test
  public void detect_weakCredentialsExist_returnsAllWeakCredentials() throws Exception {
    ajpTestServer.setResponseForCredential(
        WEAK_CRED_AUTH_1,
        Resources.toByteArray(
            Resources.getResource(this.getClass(), "testdata/successfulAuthdResponse.bin")));
    ajpTestServer.setResponseForCredential(
        WEAK_CRED_AUTH_2,
        Resources.toByteArray(
            Resources.getResource(this.getClass(), "testdata/successfulAuthdResponse.bin")));

    NetworkService targetNetworkService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(ajpTestServer.getHost(), ajpTestServer.getPort()))
            .setServiceName("ajp13")
            .setServiceContext(
                ServiceContext.newBuilder()
                    .setWebServiceContext(
                        WebServiceContext.newBuilder()
                            .setSoftware(Software.newBuilder().setName("tomcat"))))
            .build();

    assertThat(
            tester.testValidCredentials(
                targetNetworkService, ImmutableList.of(WEAK_CRED_1, WEAK_CRED_2)))
        .containsExactly(WEAK_CRED_1, WEAK_CRED_2);
    ajpTestServer.stop();
  }

  @Test
  public void detect_noWeakCredentials_returnsNoCredentials() throws Exception {
    ajpTestServer.setResponseForCredential("wrong", createAjpUnauthorizedResponse());

    NetworkService targetNetworkService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(ajpTestServer.getHost(), ajpTestServer.getPort()))
            .setServiceName("ajp13")
            .setServiceContext(
                ServiceContext.newBuilder()
                    .setWebServiceContext(
                        WebServiceContext.newBuilder()
                            .setSoftware(Software.newBuilder().setName("tomcat"))))
            .build();

    assertThat(tester.testValidCredentials(targetNetworkService, ImmutableList.of(WRONG_CRED_1)))
        .isEmpty();
    ajpTestServer.stop();
  }

  private static byte[] createAjpUnauthorizedResponse() {
    return (
            "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: "
                + "Basic realm=\"Tomcat Manager Application\"\r\n\r\n")
        .getBytes(UTF_8);
  }

  private static class AjpTestServer {
    private ServerSocket serverSocket;
    private boolean running = false;
    private final int port = 8909;
    private final String host = "localhost";
    private final Map<String, byte[]> credentialResponses = new HashMap<>();

    public void start() throws IOException {
      serverSocket = new ServerSocket(port);
      running = true;

      new Thread(
              () -> {
                while (running) {
                  try (Socket clientSocket = serverSocket.accept();
                      DataInputStream is = new DataInputStream(clientSocket.getInputStream());
                      DataOutputStream os = new DataOutputStream(clientSocket.getOutputStream())) {

                    byte[] requestBytes = new byte[8192];
                    int readBytes = is.read(requestBytes);
                    String receivedMessage =
                        new String(requestBytes, 0, readBytes, StandardCharsets.UTF_8);

                    System.out.println("Received message: " + receivedMessage);

                    String authHeader = extractAuthHeader(receivedMessage);

                    byte[] responseBytes =
                        credentialResponses.getOrDefault(
                        authHeader, createAjpUnauthorizedResponse());

                    os.write(responseBytes);
                    os.flush();

                  } catch (IOException e) {
                    System.err.println("An error occurred in AjpTestServer.");
                    e.printStackTrace();
                  }
                }
              })
          .start();
    }

    public void stop() throws IOException {
      running = false;
      if (serverSocket != null && !serverSocket.isClosed()) {
        serverSocket.close();
      }
    }

    public String getHost() {
      return host;
    }

    public int getPort() {
      return port;
    }

    public void setResponseForCredential(String credential, byte[] responseBody) {
      credentialResponses.put(credential, responseBody);
    }

    private String extractAuthHeader(String receivedMessage) {
      if (receivedMessage.contains(WEAK_CRED_AUTH_1)) {
        return WEAK_CRED_AUTH_1;
      } else if (receivedMessage.contains(WEAK_CRED_AUTH_2)) {
        return WEAK_CRED_AUTH_2;
      }
      return "wrong";
    }
  }
}