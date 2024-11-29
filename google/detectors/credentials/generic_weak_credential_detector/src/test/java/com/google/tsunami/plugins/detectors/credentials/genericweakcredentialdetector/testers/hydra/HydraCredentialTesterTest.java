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
package com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.testers.hydra;

import static com.google.common.truth.Truth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forIpAndPort;
import static org.mockito.Mockito.mock;

import com.google.common.collect.ImmutableList;
import com.google.tsunami.common.command.CommandExecutor;
import com.google.tsunami.common.command.CommandExecutorFactory;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.clients.hydra.HydraClient;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.clients.hydra.HydraClient.HydraClientCliOptions;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.proto.TargetService;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.provider.TestCredential;
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
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.Mockito;

/** Tests for {@link HydraCredentialTester}. */
@RunWith(JUnit4.class)
public final class HydraCredentialTesterTest {
  @Rule public TemporaryFolder tempFolder = new TemporaryFolder();
  private File creds;
  private File report;
  private HydraClient client;
  private HydraCredentialTester tester;
  private HydraClientCliOptions clioptions;

  @Before
  public void setupHydraCredentialTest() throws IOException {
    CommandExecutorFactory.setInstance(mock(CommandExecutor.class, Mockito.RETURNS_MOCKS));
    File hydraFile = tempFolder.newFile("hydra");
    creds = tempFolder.newFile("creds");
    report = tempFolder.newFile("report");
    clioptions = new HydraClientCliOptions();
    client = new HydraClient(hydraFile.getAbsolutePath(), true, creds, report, clioptions);
    tester = new HydraCredentialTester(() -> client);
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
  public void description_always_returnsSupportedServiceRdp() {
    assertThat(tester.description()).ignoringCase().contains("ms-wbt-server");
  }

  @Test
  public void canAccept_whenRdpService_returnsTrue() {
    NetworkService networkService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(forIpAndPort("1.1.1.1", 3389))
            .setTransportProtocol(TransportProtocol.TCP)
            .setServiceName("ms-wbt-server")
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
  public void canAccept_whenUnsupportedWebService_returnsFalse() {
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
  public void testValidCredentials_whenSupportedService_hydraIsCalledWithProvidedData() {
    NetworkService networkService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(forIpAndPort("1.1.1.1", 3389))
            .setTransportProtocol(TransportProtocol.TCP)
            .setServiceName("ms-wbt-server")
            .setVersionSet(
                VersionSet.newBuilder()
                    .addVersions(
                        Version.newBuilder()
                            .setType(VersionType.NORMAL)
                            .setFullVersionString("1.1")))
            .build();
    TestCredential testCredential = TestCredential.create("root", Optional.of("1234"));

    tester.testValidCredentials(networkService, ImmutableList.of(testCredential));

    assertThat(client.getNetworkEndpoint()).isEqualTo(forIpAndPort("1.1.1.1", 3389));
    assertThat(client.getTargetService()).isEqualTo(TargetService.RDP);
    assertThat(client.getTestCredentials()).containsExactly(testCredential);
  }

  @Test
  public void testValidCredentials_whenHydraReportsValidCredentials_returnsFoundCredentials()
      throws IOException {
    try (BufferedWriter writer =
        Files.newBufferedWriter(report.toPath(), Charset.defaultCharset())) {
      writer.write("[3389][rdp] host: 1.1.1.1   login: root   password: toor");
    }
    NetworkService networkService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(forIpAndPort("1.1.1.1", 3389))
            .setTransportProtocol(TransportProtocol.TCP)
            .setServiceName("ms-wbt-server")
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

  // TODO(b/311336843): Remove after xrdp issue is resolved
  @Test
  public void testValidCredentials_whenHydraReportsAllValidCredentials_returnsNoCredential()
      throws IOException {
    try (BufferedWriter writer =
        Files.newBufferedWriter(report.toPath(), Charset.defaultCharset())) {
      writer.write("[3389][rdp] host: 1.1.1.1   login: root   password: toor\n");
      writer.write("[3389][rdp] host: 1.1.1.1   login: root   password: admin\n");
      writer.write("[3389][rdp] host: 1.1.1.1   login: root   password: test\n");
      writer.write("[3389][rdp] host: 1.1.1.1   login: admin   password: toor\n");
      writer.write("[3389][rdp] host: 1.1.1.1   login: test   password: toor\n");
      writer.write("[3389][rdp] host: 1.1.1.1   login: user   password: toor\n");
    }
    NetworkService networkService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(forIpAndPort("1.1.1.1", 3389))
            .setTransportProtocol(TransportProtocol.TCP)
            .setServiceName("ms-wbt-server")
            .setVersionSet(
                VersionSet.newBuilder()
                    .addVersions(
                        Version.newBuilder()
                            .setType(VersionType.NORMAL)
                            .setFullVersionString("1.1")))
            .build();

    assertThat(tester.testValidCredentials(networkService, ImmutableList.of())).isEmpty();
  }

  // TODO(b/311336843): Remove after xrdp issue is resolved
  @Test
  public void testValidCredentials_whenXdrpService_returnsNoCredential() {
    NetworkService networkService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(forIpAndPort("1.1.1.1", 3389))
            .setTransportProtocol(TransportProtocol.TCP)
            .setSoftware(Software.newBuilder().setName("xrdp").build())
            .setServiceName("ms-wbt-server")
            .setVersionSet(
                VersionSet.newBuilder()
                    .addVersions(
                        Version.newBuilder()
                            .setType(VersionType.NORMAL)
                            .setFullVersionString("1.1")))
            .build();

    assertThat(tester.testValidCredentials(networkService, ImmutableList.of())).isEmpty();
  }
}
