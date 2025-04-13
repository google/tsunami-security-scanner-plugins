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

package com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.testers.rstudio;

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
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.Optional;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.inject.Inject;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for {@link RStudioCredentialTester}. */
@RunWith(JUnit4.class)
public class RStudioCredentialTesterTest {
  @Inject private RStudioCredentialTester tester;
  private MockWebServer mockWebServer;
  private static final TestCredential WEAK_CRED_1 =
      TestCredential.create("user", Optional.of("1234"));
  private static final TestCredential WEAK_CRED_2 =
      TestCredential.create("root", Optional.of("pass"));
  private static final TestCredential WRONG_CRED_1 =
      TestCredential.create("wrong", Optional.of("pass"));
  private static final ServiceContext.Builder RSTUDIO_SERVICE_CONTEXT =
      ServiceContext.newBuilder()
          .setWebServiceContext(
              WebServiceContext.newBuilder().setSoftware(Software.newBuilder().setName("rstudio")));

  @Before
  public void setup() {
    mockWebServer = new MockWebServer();
    Guice.createInjector(new HttpClientModule.Builder().build()).injectMembers(this);
  }

  // TODO: fix the intermittent test failure
  // @Test
  // public void detect_weakCredentialsExists_returnsWeakCredentials() throws Exception {
  //   startMockWebServer("/", "");
  //   NetworkService targetNetworkService =
  //       NetworkService.newBuilder()
  //           .setNetworkEndpoint(
  //               forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
  //           .setServiceName("http")
  //           .setServiceContext(RSTUDIO_SERVICE_CONTEXT)
  //           .setSoftware(Software.newBuilder().setName("http"))
  //           .build();
  //   assertThat(tester.testValidCredentials(targetNetworkService, ImmutableList.of(WEAK_CRED_1)))
  //       .containsExactly(WEAK_CRED_1);
  //   mockWebServer.shutdown();
  // }
  //
  // TODO: fix the intermittent test failure
  // @Test
  // public void detect_weakCredentialsExist_returnsFirstWeakCredentials() throws Exception {
  //   startMockWebServer("/", "");
  //   NetworkService targetNetworkService =
  //       NetworkService.newBuilder()
  //           .setNetworkEndpoint(
  //               forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
  //           .setServiceName("http")
  //           .setServiceContext(RSTUDIO_SERVICE_CONTEXT)
  //           .build();

  //   assertThat(
  //           tester.testValidCredentials(
  //               targetNetworkService, ImmutableList.of(WEAK_CRED_1, WEAK_CRED_2)))
  //       .containsExactly(WEAK_CRED_1);
  //   mockWebServer.shutdown();
  // }

  @Test
  public void detect_noWeakCredentials_returnsNoCredentials() throws Exception {
    startMockWebServer("/", "");
    NetworkService targetNetworkService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .setServiceName("http")
            .setServiceContext(RSTUDIO_SERVICE_CONTEXT)
            .build();

    assertThat(tester.testValidCredentials(targetNetworkService, ImmutableList.of(WRONG_CRED_1)))
        .isEmpty();
    mockWebServer.shutdown();
  }

  private void startMockWebServer(String url, String response) throws IOException {
    mockWebServer.setDispatcher(new RespondUserInfoResponseDispatcher(response));
    mockWebServer.start();
    mockWebServer.url(url);
  }

  static final class RespondUserInfoResponseDispatcher extends Dispatcher {
    private KeyPair pair;

    RespondUserInfoResponseDispatcher(String authenticatedUserResponse) {
      try {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        this.pair = keyGen.generateKeyPair();
      } catch (NoSuchAlgorithmException e) {
        this.pair = null;
      }
    }

    @Override
    public MockResponse dispatch(RecordedRequest recordedRequest) {
      try {
        var isUserEndpoint = recordedRequest.getPath().startsWith("/auth-do-sign-in");
        var isPublicKeyEndpoint = recordedRequest.getPath().startsWith("/auth-public-key");

        RSAPrivateKey privateKey = (RSAPrivateKey) this.pair.getPrivate();
        RSAPublicKey publicKey = (RSAPublicKey) this.pair.getPublic();

        if (isUserEndpoint) {
          var ciphertext =
              recordedRequest
                  .getBody()
                  .readUtf8()
                  .toString()
                  .split("&v=")[1]
                  .trim()
                  .replaceAll("\\%2b", "+")
                  .replaceAll("\\%3d", "=");
          Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
          cipher.init(Cipher.DECRYPT_MODE, privateKey);

          byte[] b64Decoded = Base64.getDecoder().decode(ciphertext);
          byte[] cipherData = cipher.doFinal(b64Decoded);

          String creds = new String(cipherData, StandardCharsets.UTF_8);

          String username = creds.toString().split("\n")[0].trim();
          String password = creds.toString().split("\n")[1].trim();
          boolean hasWeakCred1 =
              username.equals(WEAK_CRED_1.username())
                  && password.equals(WEAK_CRED_1.password().get());
          boolean hasWeakCred2 =
              username.equals(WEAK_CRED_2.username())
                  && password.equals(WEAK_CRED_2.password().get());
          if (hasWeakCred1 || hasWeakCred2) {
            return new MockResponse()
                .setResponseCode(HttpStatus.OK.code())
                .setHeader("Set-Cookie", "user-id=" + username + "|");
          }
        } else if (isPublicKeyEndpoint) {
          StringBuilder sb = new StringBuilder();
          for (byte b : publicKey.getPublicExponent().toByteArray()) {
            sb.append(String.format("%02X", b));
          }
          sb.append(":");
          for (byte b : publicKey.getModulus().toByteArray()) {
            sb.append(String.format("%02X", b));
          }
          return new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody(sb.toString());
        }
        return new MockResponse().setResponseCode(HttpStatus.UNAUTHORIZED.code());
      } catch (NoSuchAlgorithmException
          | NoSuchPaddingException
          | InvalidKeyException
          | IllegalBlockSizeException
          | BadPaddingException e) {
        return new MockResponse().setResponseCode(HttpStatus.UNAUTHORIZED.code());
      }
    }
  }
}
