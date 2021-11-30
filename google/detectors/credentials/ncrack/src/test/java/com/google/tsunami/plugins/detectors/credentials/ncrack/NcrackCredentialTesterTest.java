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
package com.google.tsunami.plugins.detectors.credentials.ncrack;

import static com.google.common.truth.Truth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forIpAndPort;
import static org.mockito.Mockito.mock;

import com.google.common.collect.ImmutableList;
import com.google.tsunami.common.command.CommandExecutor;
import com.google.tsunami.common.command.CommandExecutorFactory;
import com.google.tsunami.plugins.detectors.credentials.ncrack.client.NcrackClient;
import com.google.tsunami.plugins.detectors.credentials.ncrack.client.NcrackClient.TargetService;
import com.google.tsunami.plugins.detectors.credentials.ncrack.provider.TestCredential;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.Software;
import com.google.tsunami.proto.TransportProtocol;
import com.google.tsunami.proto.Version;
import com.google.tsunami.proto.Version.VersionType;
import com.google.tsunami.proto.VersionSet;
import java.io.BufferedWriter;
import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.util.Optional;
import java.util.concurrent.Executors;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.Mockito;

/** Tests for {@link NcrackCredentialTester}. */
@RunWith(JUnit4.class)
public final class NcrackCredentialTesterTest {

  @Rule public TemporaryFolder tempFolder = new TemporaryFolder();
  private File report;
  private NcrackClient client;
  private NcrackCredentialTester tester;

  @Before
  public void setupNcrackCredentialTest() throws IOException {
    CommandExecutorFactory.setInstance(mock(CommandExecutor.class, Mockito.RETURNS_MOCKS));
    File ncrackFile = tempFolder.newFile("ncrack");
    report = tempFolder.newFile("report");
    client = new NcrackClient(ncrackFile.getAbsolutePath(), report);
    tester = new NcrackCredentialTester(() -> client, Executors.newCachedThreadPool());
  }

  @Test
  public void name_always_doNotReturnEmptyOrNull() {
    assertThat(tester.name()).isNotNull();
    assertThat(tester.name()).isNotEmpty();
  }

  @Test
  public void description_always_doNotReturnEmptyOrNull() {
    assertThat(tester.description()).isNotNull();
    assertThat(tester.description()).isNotEmpty();
  }

  @Test
  public void description_always_returnsSupportedServiceSshAndRdp() {
    assertThat(tester.description()).ignoringCase().contains("ssh");
    assertThat(tester.description()).ignoringCase().contains("rdp");
  }

  @Test
  public void canAccept_whenWordPressService_returnsTrue() {
    NetworkService networkService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(forIpAndPort("1.1.1.1", 22))
            .setTransportProtocol(TransportProtocol.TCP)
            .setServiceName("http")
            .setSoftware(Software.newBuilder().setName("WordPress"))
            .setVersionSet(
                VersionSet.newBuilder()
                    .addVersions(
                        Version.newBuilder()
                            .setType(VersionType.NORMAL)
                            .setFullVersionString("1.1")))
            .build();

    assertThat(tester.canAccept(networkService)).isTrue();
  }

  @Test
  public void canAccept_whenUnsupportedWebService_returnsTrue() {
    NetworkService networkService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(forIpAndPort("1.1.1.1", 22))
            .setTransportProtocol(TransportProtocol.TCP)
            .setServiceName("http")
            .setSoftware(Software.newBuilder().setName("Jenkins"))
            .setVersionSet(
                VersionSet.newBuilder()
                    .addVersions(
                        Version.newBuilder()
                            .setType(VersionType.NORMAL)
                            .setFullVersionString("1.1")))
            .build();

    assertThat(tester.canAccept(networkService)).isFalse();
  }

  @Test
  public void canAccept_whenSupportedService_returnsTrue() {
    NetworkService networkService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(forIpAndPort("1.1.1.1", 22))
            .setTransportProtocol(TransportProtocol.TCP)
            .setServiceName("ssh")
            .setSoftware(Software.newBuilder().setName("OpenSSH"))
            .setVersionSet(
                VersionSet.newBuilder()
                    .addVersions(
                        Version.newBuilder()
                            .setType(VersionType.NORMAL)
                            .setFullVersionString("1.1")))
            .build();

    assertThat(tester.canAccept(networkService)).isTrue();
  }

  @Test
  public void canAccept_whenUnsupportedService_returnsFalse() {
    NetworkService networkService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(forIpAndPort("1.1.1.1", 9090))
            .setTransportProtocol(TransportProtocol.TCP)
            .setServiceName("proxy")
            .setSoftware(Software.newBuilder().setName("Open Proxy"))
            .setVersionSet(
                VersionSet.newBuilder()
                    .addVersions(
                        Version.newBuilder()
                            .setType(VersionType.NORMAL)
                            .setFullVersionString("1.1")))
            .build();

    assertThat(tester.canAccept(networkService)).isFalse();
  }

  @Test
  public void testValidCredentials_whenUnsupportedService_returnsEmptyList() {
    NetworkService networkService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(forIpAndPort("1.1.1.1", 9090))
            .setTransportProtocol(TransportProtocol.TCP)
            .setServiceName("proxy")
            .setSoftware(Software.newBuilder().setName("Open Proxy"))
            .setVersionSet(
                VersionSet.newBuilder()
                    .addVersions(
                        Version.newBuilder()
                            .setType(VersionType.NORMAL)
                            .setFullVersionString("1.1")))
            .build();

    assertThat(tester.testValidCredentials(networkService, ImmutableList.of())).isEmpty();
  }

  @Test
  public void testValidCredentials_whenSupportedService_NcrackIsCalledWithProvidedData() {
    NetworkService networkService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(forIpAndPort("1.1.1.1", 22))
            .setTransportProtocol(TransportProtocol.TCP)
            .setServiceName("ssh")
            .setSoftware(Software.newBuilder().setName("OpenSSH"))
            .setVersionSet(
                VersionSet.newBuilder()
                    .addVersions(
                        Version.newBuilder()
                            .setType(VersionType.NORMAL)
                            .setFullVersionString("1.1")))
            .build();

    tester.testValidCredentials(
        networkService, ImmutableList.of(TestCredential.create("root", Optional.of("1234"))));

    assertThat(client.getNetworkEndpoints()).containsExactly(forIpAndPort("1.1.1.1", 22));
    assertThat(client.getTargetService()).isEqualTo(TargetService.SSH);
    assertThat(client.getUsernameList()).containsExactly("root");
    assertThat(client.getPasswordList()).containsExactly("1234");
  }

  @Test
  public void testValidCredentials_whenNcrackReportsValidCredentials_returnsFoundCredentials()
      throws IOException {
    try (BufferedWriter writer =
        Files.newBufferedWriter(report.toPath(), Charset.defaultCharset())) {
      writer.write("1.1.1.1 8888/tcp http: 'root' 'toor'");
    }
    NetworkService networkService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(forIpAndPort("1.1.1.1", 22))
            .setTransportProtocol(TransportProtocol.TCP)
            .setServiceName("ssh")
            .setSoftware(Software.newBuilder().setName("OpenSSH"))
            .setVersionSet(
                VersionSet.newBuilder()
                    .addVersions(
                        Version.newBuilder()
                            .setType(VersionType.NORMAL)
                            .setFullVersionString("1.1")))
            .build();

    assertThat(tester.testValidCredentials(networkService, ImmutableList.of()))
        .containsExactly(TestCredential.create("root", Optional.of("toor")));
  }
}
