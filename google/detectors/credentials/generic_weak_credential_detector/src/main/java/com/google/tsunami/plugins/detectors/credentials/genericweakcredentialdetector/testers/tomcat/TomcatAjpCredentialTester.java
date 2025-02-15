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

package com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.testers.tomcat;

import static com.google.common.collect.ImmutableList.toImmutableList;
import static java.nio.charset.StandardCharsets.UTF_8;

import com.doyensec.ajp13.AjpMessage;
import com.doyensec.ajp13.AjpReader;
import com.doyensec.ajp13.ForwardRequestMessage;
import com.doyensec.ajp13.Pair;
import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.tsunami.common.data.NetworkEndpointUtils;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.provider.TestCredential;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.tester.CredentialTester;
import com.google.tsunami.proto.NetworkService;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.util.Base64;
import java.util.LinkedList;
import java.util.List;
import javax.inject.Inject;

/** Credential tester for Tomcat using AJP. */
public final class TomcatAjpCredentialTester extends CredentialTester {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private static final String AJP13_SERVICE = "ajp13";
  private static final String TOMCAT_COOKIE_SET = "set-cookie: JSESSIONID";
  private static final String TOMCAT_AUTH_HEADER = "Basic realm=\"Tomcat Manager Application\"";

  @Inject
  TomcatAjpCredentialTester() {
  }

  @Override
  public String name() {
    return "TomcatAjpCredentialTester";
  }

  @Override
  public boolean batched() {
    return true;
  }

  @Override
  public String description() {
    return "Tomcat AJP credential tester.";
  }

  @Override
  public boolean canAccept(NetworkService networkService) {

    var uriAuthority = NetworkEndpointUtils.toUriAuthority(networkService.getNetworkEndpoint());

    boolean canAcceptByNmapReport =
        NetworkServiceUtils.getWebServiceName(networkService).equals(AJP13_SERVICE);

    if (!canAcceptByNmapReport) {
      return false;
    }

    boolean canAcceptByCustomFingerprint = false;

    String[] uriParts = uriAuthority.split(":");
    String host = uriParts[0];
    int port = Integer.parseInt(uriParts[1]);

    // Check if the server response indicates a redirection to /manager/html.
    // This typically means that the Tomcat Manager is active and automatically
    // redirects users to the management interface when accessing the base manager URL.
    try {
      logger.atInfo().log("probing Tomcat manager - custom fingerprint phase using AJP");

      List<Pair<String, String>> headers = new LinkedList<>();
      List<Pair<String, String>> attributes = new LinkedList<>();
      AjpMessage request = new ForwardRequestMessage(
          2, "HTTP/1.1", "/manager/html", host, host, host, port, true, headers, attributes);

      byte[] response = sendAndReceive(host, port, request.getBytes());
      AjpMessage responseMessage = AjpReader.parseMessage(response);

      canAcceptByCustomFingerprint = responseMessage.getDescription()
        .toLowerCase().contains(TOMCAT_AUTH_HEADER.toLowerCase());

    } catch (NullPointerException e) {
      logger.atWarning().log("Unable to query '%s'.", uriAuthority);
      return false;
    } catch (IOException e){
      logger.atWarning().log("Unable to query '%s'.", uriAuthority);
      return false;
    }

    return canAcceptByCustomFingerprint;
  }

  @Override
  public ImmutableList<TestCredential> testValidCredentials(
      NetworkService networkService, List<TestCredential> credentials) {

    return credentials.stream()
        .filter(cred -> isTomcatAccessible(networkService, cred))
        .collect(toImmutableList());
  }

  private boolean isTomcatAccessible(NetworkService networkService, TestCredential credential) {
    var uriAuthority = NetworkEndpointUtils.toUriAuthority(networkService.getNetworkEndpoint());
    String[] uriParts = uriAuthority.split(":");
    String host = uriParts[0];
    int port = Integer.parseInt(uriParts[1]);
    var url = String.format("%s/%s", uriAuthority, "manager/html");
    
    logger.atInfo().log("uriAuthority: %s", uriAuthority);
    try {
      logger.atInfo().log(
          "url: %s, username: %s, password: %s",
          url, credential.username(), credential.password().orElse(""));
      
      String authorization = "Basic " + Base64.getEncoder()
          .encodeToString((credential.username() + ":" + credential.password().orElse(""))
          .getBytes(UTF_8));
      
      List<Pair<String, String>> headers = new LinkedList<>();
      headers.add(Pair.make("Authorization", authorization));
      List<Pair<String, String>> attributes = new LinkedList<>();
      
      AjpMessage request = new ForwardRequestMessage(
          2, "HTTP/1.1", "/manager/html", host, host, host, port, true, headers, attributes);

      byte[] response = sendAndReceive(host, port, request.getBytes());
      AjpMessage responseMessage = AjpReader.parseMessage(response);

      return headersContainsSuccessfulLoginElements(responseMessage);
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Unable to query '%s'.", url);
      return false;
    }
  }


  // This methods send the AjpMessage generated via sockets and return the response from the server 
  private byte[] sendAndReceive(String host, int port, byte[] data) throws IOException {
    try (Socket socket = new Socket(host, port)) {
      DataOutputStream os = new DataOutputStream(socket.getOutputStream());
      DataInputStream is = new DataInputStream(socket.getInputStream());

      os.write(data);
      os.flush();

      byte[] buffReply = new byte[8192];
      int bytesRead = is.read(buffReply);

      if (bytesRead > 0) {
        byte[] fullReply = new byte[bytesRead];
        System.arraycopy(buffReply, 0, fullReply, 0, bytesRead);

        return fullReply;
      }
      return new byte[0];
    } catch (IOException e) {
      logger.atSevere().withCause(e).log("Error sendind the AjpMessage");
      throw e;
    }
  }

  // This method checks if the response headers contain elements indicative of a Tomcat manager 
  // page. Specifically, it examines the cookies set rather than body elements to improve the 
  // efficiency and speed of the plugin. By focusing on headers, the plugin can quickly identify 
  // successful logins without parsing potentially large and variable body content.
  private static boolean headersContainsSuccessfulLoginElements(AjpMessage responseMessage) {
    try {
      String responseHeaders = responseMessage.getDescription().toLowerCase();
      if (responseHeaders.contains(TOMCAT_COOKIE_SET.toLowerCase())) {
        logger.atInfo().log(
            "Found Tomcat endpoint (TOMCAT_COOKIE_SET string present in the page)");
        return true;
      } else {
        return false;
      }
    } catch (Exception e) {
      logger.atWarning().withCause(e).log(
          "An error occurred in headersContainsSuccessfulLoginElements");
      return false;
    }
  }
}
