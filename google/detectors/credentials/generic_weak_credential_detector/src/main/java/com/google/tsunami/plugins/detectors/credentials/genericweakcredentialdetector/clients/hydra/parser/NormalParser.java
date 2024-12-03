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
package com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.clients.hydra.parser;

import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostnameAndPort;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forIpAndPort;
import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.common.net.InetAddresses;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.clients.common.DiscoveredCredential;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.clients.hydra.data.HydraRun;
import com.google.tsunami.proto.NetworkEndpoint;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parser for hydra normal report.
 *
 * <p>Hydra output looks like the following:
 *
 * <p>[<port>][<service>] host: [<server>]  login <username>   password: <password>
 *
 * <p>Example: <code>
 * # Hydra v9.1 run at 2023-12-13 23:45:03 on 34.72.36.77 rdp (hydra -L user.txt -P pass.txt
 * -o report.txt -s 3389 34.72.36.77 rdp)
 * [3389][rdp] host: 34.72.36.77   login: admin   password: admin
 * [3389][rdp] host: 34.72.36.77   login: root   password: test
 */
public class NormalParser {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  private static final Pattern CREDENTIAL_LINE_PATTERN =
      Pattern.compile(
          "^\\[(?<port>\\d+)]\\[(?<service>\\w+)]\\s+host:\\s+(?<ip>.+?)\\s+login:\\s+(?<username>.*?)\\s+password:\\s+(?<password>.*)");

  public static HydraRun parse(InputStream stream) throws IOException {
    BufferedReader reader = new BufferedReader(new InputStreamReader(stream, UTF_8));
    ImmutableList.Builder<DiscoveredCredential> credentialBuilder = ImmutableList.builder();

    String line;
    while ((line = reader.readLine()) != null) {
      Matcher matcher = CREDENTIAL_LINE_PATTERN.matcher(line);
      if (matcher.find()) {
        String ip = matcher.group("ip");
        int port = Integer.parseInt(matcher.group("port"));
        String service = matcher.group("service");
        Optional<String> username = Optional.ofNullable(matcher.group("username"));
        Optional<String> password = Optional.ofNullable(matcher.group("password"));
        logger.atInfo().log(
            "Hydra identified known credentials on '%s' port '%d' for '%s' service, username ="
                + " '%s', password = '%s'.",
            ip, port, service, username.orElse(""), password.orElse(""));
        credentialBuilder.add(
            DiscoveredCredential.builder()
                .setNetworkEndpoint(createNetworkEndpoint(ip, port))
                .setService(service)
                .setUsername(username)
                .setPassword(password)
                .build());
      }
    }
    return HydraRun.create(credentialBuilder.build());
  }

  private static NetworkEndpoint createNetworkEndpoint(String target, int port) {
    return InetAddresses.isInetAddress(target)
        ? forIpAndPort(target, port)
        : forHostnameAndPort(target, port);
  }

  private NormalParser() {}
}
