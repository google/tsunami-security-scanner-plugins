/*
 * Copyright 2020 Google LLC
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
package com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.clients.ncrack.parser;

import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostnameAndPort;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forIpAndPort;
import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.common.net.InetAddresses;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.clients.common.DiscoveredCredential;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.clients.ncrack.data.NcrackRun;
import com.google.tsunami.proto.NetworkEndpoint;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parser for ncrack normal report.
 *
 * <p>Ncrack put the discovered username and password between single quotes but will not escape them
 * if the credentials contains single quotes.
 *
 * <p>Based on the source code, discovered credentials for a specific service always start with a
 * line like <code>
 * "Discovered credentials for (service) on (ip) (optional: hostname) (port)/(protocol)"
 * </code>, followed by one or more credential lines formatted as <code>
 * "(ip) (port)/(protocol) (service): '(username)' '(password)'"</code>.
 *
 * <p>Source:
 * https://github.com/nmap/ncrack/blob/20e010c5efc856ccdd35d850230792aca62047ab/output.cc#L486
 *
 * <p>Example: <code>
 * Discovered credentials for ftp on 10.0.0.130 21/tcp:
 * 10.0.0.130 21/tcp ftp: 'admin' 'hello1'
 * Discovered credentials for ssh on 192.168.1.2 22/tcp:
 * 192.168.1.2 22/tcp ssh: 'guest' '12345'
 * 192.168.1.2 22/tcp ssh: 'admin' 'money$'</code>
 */
public class NormalParser {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  private static final Pattern CREDENTIAL_LINE_PATTERN =
      Pattern.compile(
          "^(?<ip>.+) (?<port>\\d+)/(?<protocol>\\w+) (?<service>\\w+): '(?<username>.*)'"
              + " '(?<password>.*)'");

  public static NcrackRun parse(InputStream stream) throws IOException {
    BufferedReader reader = new BufferedReader(new InputStreamReader(stream, UTF_8));
    ImmutableList.Builder<DiscoveredCredential> credentialBuilder = ImmutableList.builder();

    String line;
    while ((line = reader.readLine()) != null) {
      Matcher matcher = CREDENTIAL_LINE_PATTERN.matcher(line);
      if (matcher.find()) {
        String ip = matcher.group("ip");
        int port = Integer.parseInt(matcher.group("port"));
        String protocol = matcher.group("protocol");
        String service = matcher.group("service");
        Optional<String> username = Optional.ofNullable(matcher.group("username"));
        Optional<String> password = Optional.ofNullable(matcher.group("password"));
        logger.atInfo().log(
            "Ncrack identified known credentials on '%s' port '%d' for '%s' service and '%s'"
                + " protocol, username = '%s', password = '%s'.",
            ip, port, service, protocol, username.orElse(""), password.orElse(""));
        credentialBuilder.add(
            DiscoveredCredential.builder()
                .setNetworkEndpoint(createNetworkEndpoint(ip, port))
                .setService(service)
                .setUsername(username)
                .setPassword(password)
                .build());
      }
    }
    return NcrackRun.create(credentialBuilder.build());
  }

  private static NetworkEndpoint createNetworkEndpoint(String target, int port) {
    return InetAddresses.isInetAddress(target)
        ? forIpAndPort(target, port)
        : forHostnameAndPort(target, port);
  }

  private NormalParser() {}
}
