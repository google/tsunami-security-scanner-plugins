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
package com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.clients.ncrack.parser;

import static com.google.common.truth.Truth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forIpAndPort;
import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.clients.common.DiscoveredCredential;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.clients.ncrack.data.NcrackRun;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for {@link NormalParser}. */
@RunWith(JUnit4.class)
public class NormalParserTest {

  @Test
  public void parse_whenTargetIsIPv4AndAllFieldsPresents_extractsAllFields() throws IOException {
    String line =
        "Discovered credentials for http on 1.1.1.1 8888/tcp:\n"
            + "1.1.1.1 8888/tcp http: 'root' 'toor'";
    InputStream stream = new ByteArrayInputStream(line.getBytes(UTF_8));

    NcrackRun run = NormalParser.parse(stream);

    assertThat(run.discoveredCredentials())
        .containsExactly(
            DiscoveredCredential.builder()
                .setNetworkEndpoint(forIpAndPort("1.1.1.1", 8888))
                .setService("http")
                .setUsername("root")
                .setPassword("toor")
                .build());
  }

  @Test
  public void parse_whenTargetIsMultipleLines_extractsAllFields() throws IOException {
    String line =
        "Discovered credentials for http on 1.1.1.1 8888/tcp:\n"
            + "1.1.1.1 8888/tcp http: 'root' 'toor'\n"
            + "Discovered credentials for ftp on 1.1.1.2 8888/tcp:\n"
            + "1.1.1.2 8888/tcp ftp: 'root' 'toor'";
    InputStream stream = new ByteArrayInputStream(line.getBytes(UTF_8));

    NcrackRun run = NormalParser.parse(stream);

    assertThat(run.discoveredCredentials())
        .containsExactly(
            DiscoveredCredential.builder()
                .setNetworkEndpoint(forIpAndPort("1.1.1.1", 8888))
                .setService("http")
                .setUsername("root")
                .setPassword("toor")
                .build(),
            DiscoveredCredential.builder()
                .setNetworkEndpoint(forIpAndPort("1.1.1.2", 8888))
                .setService("ftp")
                .setUsername("root")
                .setPassword("toor")
                .build());
  }

  @Test
  public void parse_withIPv6Target_extractsAllFields() throws IOException {
    String line =
        "Discovered credentials for http on 2001:4860:4860::8888 8888/tcp:\n"
            + "2001:4860:4860::8888 8888/tcp http: 'root' 'toor'";
    InputStream stream = new ByteArrayInputStream(line.getBytes(UTF_8));

    NcrackRun run = NormalParser.parse(stream);

    assertThat(run.discoveredCredentials())
        .containsExactly(
            DiscoveredCredential.builder()
                .setNetworkEndpoint(forIpAndPort("2001:4860:4860::8888", 8888))
                .setService("http")
                .setUsername("root")
                .setPassword("toor")
                .build());
  }

  @Test
  public void parse_whenCredentialsWithComma_extractsAllFields() throws IOException {
    String line =
        "Discovered credentials for http on 1.1.1.1 8888/tcp:\n"
            + "1.1.1.1 8888/tcp http: ''root' 'toor'";
    InputStream stream = new ByteArrayInputStream(line.getBytes(UTF_8));

    NcrackRun run = NormalParser.parse(stream);

    assertThat(run.discoveredCredentials())
        .containsExactly(
            DiscoveredCredential.builder()
                .setNetworkEndpoint(forIpAndPort("1.1.1.1", 8888))
                .setService("http")
                .setUsername("'root")
                .setPassword("toor")
                .build());
  }
}
