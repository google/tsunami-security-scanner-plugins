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

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.tsunami.common.net.http.HttpRequest.get;
import static com.google.tsunami.common.net.http.HttpRequest.post;

import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.protobuf.ByteString;
import com.google.tsunami.common.data.NetworkEndpointUtils;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpHeaders;
import com.google.tsunami.common.net.http.HttpResponse;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.provider.TestCredential;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.tester.CredentialTester;
import com.google.tsunami.proto.NetworkService;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.List;
import java.util.Base64;
import java.util.Optional;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.inject.Inject;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;

/** Credential tester for RStudio. */
public final class RStudioCredentialTester extends CredentialTester {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  private final HttpClient httpClient;

  private static final String RSTUDIO_SERVICE = "rstudio";
  private static final String RSTUDIO_HEADER = "RStudio";
  private static final String SERVER_HEADER = "Server";
  private static final String RSTUDIO_UNSUPPORTED_BROWSER_TITLE = "RStudio: Browser Not Supported";
  private static final String RSTUDIO_UNSUPPORTED_BROWSER_P =
      "Your web browser is not supported by RStudio.";

  @Inject
  RStudioCredentialTester(HttpClient httpClient) {
    this.httpClient = checkNotNull(httpClient).modify().setFollowRedirects(false).build();
  }

  @Override
  public String name() {
    return "RStudioCredentialTester";
  }

  @Override
  public boolean batched() {
    return false;
  }

  @Override
  public String description() {
    return "RStudio credential tester.";
  }

  private static String buildTargetUrl(NetworkService networkService, String path) {
    StringBuilder targetUrlBuilder = new StringBuilder();

    if (NetworkServiceUtils.isWebService(networkService)) {
      targetUrlBuilder.append(NetworkServiceUtils.buildWebApplicationRootUrl(networkService));
    } else {
      // Default to HTTP protocol when the scanner cannot identify the actual service.
      targetUrlBuilder
          .append("http://")
          .append(NetworkEndpointUtils.toUriAuthority(networkService.getNetworkEndpoint()))
          .append("/");
    }
    targetUrlBuilder.append(path);
    return targetUrlBuilder.toString();
  }

  /**
   * Determines if this tester can accept the {@link NetworkService} based on the name of the
   * service or a custom fingerprint. The fingerprint is necessary since nmap doesn't recognize a
   * rstudio server instance correctly.
   *
   * @param networkService the network service passed by tsunami
   * @return true if a rstudio server instance is recognized
   */
  @Override
  public boolean canAccept(NetworkService networkService) {
    boolean canAcceptByNmapReport =
        NetworkServiceUtils.getWebServiceName(networkService).equals(RSTUDIO_SERVICE);
    if (canAcceptByNmapReport) {
      return true;
    }
    boolean canAcceptByCustomFingerprint = false;
    String url = buildTargetUrl(networkService, "unsupported_browser.htm");
    try {
      logger.atInfo().log("Probing RStudio - custom fingerprint phase");
      HttpResponse response = httpClient.send(get(url).withEmptyHeaders().build());
      canAcceptByCustomFingerprint =
          response.status().isSuccess()
              && response.headers().get(SERVER_HEADER).isPresent()
              && response.headers().get(SERVER_HEADER).get().equals(RSTUDIO_HEADER)
              && response
                  .bodyString()
                  .map(RStudioCredentialTester::bodyContainsRStudioElements)
                  .orElse(false);
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Unable to query '%s'.", url);
      return false;
    }
    return canAcceptByCustomFingerprint;
  }

  private static boolean bodyContainsRStudioElements(String responseBody) {
    Document doc = Jsoup.parse(responseBody);
    String title = doc.title();
    String p =
        doc.body().getElementsByTag("p").first().outerHtml().split("<p>")[1].split("</p>")[0];

    if (title.contains(RSTUDIO_UNSUPPORTED_BROWSER_TITLE)
        && p.contains(RSTUDIO_UNSUPPORTED_BROWSER_P)) {
      logger.atInfo().log("Found RStudio endpoint");
      return true;
    } else {
      return false;
    }
  }

  @Override
  public ImmutableList<TestCredential> testValidCredentials(
      NetworkService networkService, List<TestCredential> credentials) {

    return credentials.stream()
        .filter(cred -> isRStudioAccessible(networkService, cred))
        .findFirst()
        .map(ImmutableList::of)
        .orElseGet(ImmutableList::of);
  }

  private boolean isRStudioAccessible(NetworkService networkService, TestCredential credential) {
    var url = buildTargetUrl(networkService, "auth-public-key");
    try {
      logger.atInfo().log("Retrieving public key");
      HttpResponse response = httpClient.send(get(url).withEmptyHeaders().build());
      Optional<String> body = response.bodyString();
      String exponent = body.get().split(":")[0];
      String modulus = body.get().split(":")[1];

      url = buildTargetUrl(networkService, "auth-do-sign-in");
      logger.atInfo().log(
          "url: %s, username: %s, password: %s",
          url, credential.username(), credential.password().orElse(""));
      response = sendRequestWithCredentials(url, credential, exponent, modulus);

      if (response.headers().get("Set-Cookie").isPresent()) {
        for (String s : response.headers().getAll("Set-Cookie")) {
          if (s.contains("user-id=" + credential.username())) {
            logger.atInfo().log("Found valid credentials");
            return true;
          }
        }
      } else {
        return false;
      }
    } catch (IOException
        | NoSuchProviderException
        | NoSuchAlgorithmException
        | BadPaddingException
        | IllegalBlockSizeException
        | InvalidKeyException
        | NoSuchPaddingException
        | InvalidKeySpecException e) {
      logger.atWarning().withCause(e).log("Unable to query '%s'.", url);
    }
    return false;
  }

  // This function base64 encodes provided cipertext string in hex.
  private String hexToBase64(String hex) {
    return Base64.getEncoder().encodeToString(new BigInteger(hex, 16).toByteArray());
  }

  private HttpResponse sendRequestWithCredentials(
      String url, TestCredential credential, String exponent, String modulus)
      throws NoSuchAlgorithmException,
          BadPaddingException,
          IllegalBlockSizeException,
          InvalidKeyException,
          NoSuchPaddingException,
          InvalidKeySpecException,
          IOException,
          NoSuchProviderException {
    // Encrypting with RSA PCKS#1 version 2.
    RSAPublicKeySpec spec =
        new RSAPublicKeySpec(new BigInteger(modulus, 16), new BigInteger(exponent, 16));
    KeyFactory factory = KeyFactory.getInstance("RSA");
    RSAPublicKey key = (RSAPublicKey) factory.generatePublic(spec);

    Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
    cipher.init(Cipher.ENCRYPT_MODE, key);

    StringBuilder sb = new StringBuilder();
    sb.append(credential.username());
    sb.append("\n");
    sb.append(credential.password().get());
    byte[] cipherData = cipher.doFinal(sb.toString().getBytes());

    // Converting the ciphertext to hex.
    sb = new StringBuilder();
    for (byte b : cipherData) {
      sb.append(String.format("%02X", b));
    }

    String ciphertext = this.hexToBase64(sb.toString().toLowerCase());
    var headers =
        HttpHeaders.builder()
            .addHeader("Cookie", "rs-csrf-token=1")
            .addHeader("Content-Type", "application/x-www-form-urlencoded")
            .build();

    sb = new StringBuilder();
    sb.append("rs-csrf-token=1&");
    sb.append("v=" + ciphertext.replaceAll("\\+", "%2b").replaceAll("=", "%3d"));
    return httpClient.send(
        post(url)
            .setHeaders(headers)
            .setRequestBody(ByteString.copyFrom(sb.toString().getBytes()))
            .build());
  }
}
