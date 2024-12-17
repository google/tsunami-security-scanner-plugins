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
package com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.clients.hydra;

import static com.google.common.truth.Truth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forIp;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forIpAndPort;
import static org.junit.Assert.assertThrows;
import static org.mockito.Mockito.RETURNS_SMART_NULLS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.google.common.collect.ImmutableList;
import com.google.tsunami.common.command.CommandExecutor;
import com.google.tsunami.common.command.CommandExecutorFactory;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.clients.common.DiscoveredCredential;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.clients.hydra.HydraClient.HydraClientCliOptions;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.clients.hydra.data.HydraRun;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.proto.TargetService;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.provider.TestCredential;
import java.io.BufferedWriter;
import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;

/** Tests for {@link HydraClient}. */
@RunWith(JUnit4.class)
public class HydraClientTest {
  @Rule public final MockitoRule mocks = MockitoJUnit.rule();

  private static final TestCredential CRED1 = TestCredential.create("root", Optional.of("toor"));
  private static final TestCredential CRED2 =
      TestCredential.create("admin", Optional.of("password"));
  @Rule public TemporaryFolder tempFolder = new TemporaryFolder();
  private File hydraFile;
  private File creds;
  private File report;
  private HydraClient client;
  private HydraClientCliOptions clioptions;

  @Mock CommandExecutor commandExecutor;

  @Before
  public void setup() throws IOException {
    CommandExecutorFactory.setInstance(commandExecutor);
    hydraFile = tempFolder.newFile("hydra");
    creds = tempFolder.newFile("creds");
    report = tempFolder.newFile("report");
    clioptions = new HydraClientCliOptions();
    client = new HydraClient(hydraFile.getAbsolutePath(), true, creds, report, clioptions);
  }

  @Test
  public void newClient_whenHydraClientDoesNotExist_throwsException() throws Exception {
    assertThrows(
        IllegalArgumentException.class,
        () -> new HydraClient("fileNotExist", true, creds, report, null));
  }

  @Test
  public void buildRunCommandArgs_withIpv4TargetAndRdpService_returnsCorrectCommandLine() {
    client
        .withNetworkEndpoint(forIpAndPort("1.1.1.1", 3389))
        .onTargetService(TargetService.RDP)
        .usingUsernamePasswordPair(ImmutableList.of(CRED1, CRED2));

    assertThat(client.buildRunCommandArgs())
        .containsExactly(
            hydraFile.getAbsolutePath(),
            "-C",
            creds.getAbsolutePath(),
            "-o",
            report.getAbsolutePath(),
            "rdp://1.1.1.1:3389");
  }

  @Test
  public void buildRunCommandArgs_withIpv6TargetAndSshService_returnsCorrectCommandLine() {
    client
        .withNetworkEndpoint(forIp("2001:4860:4860::8844"))
        .onTargetService(TargetService.RDP)
        .usingUsernamePasswordPair(ImmutableList.of(CRED1, CRED2));

    assertThat(client.buildRunCommandArgs())
        .containsExactly(
            hydraFile.getAbsolutePath(),
            "-C",
            creds.getAbsolutePath(),
            "-6",
            "-o",
            report.getAbsolutePath(),
            "rdp://[2001:4860:4860::8844]");
  }

  @Test
  public void buildRunCommandArgs_withQuitCrackingAfterOneFound_returnsCorrectCommandLine()
      throws Exception {
    client
        .withNetworkEndpoint(forIpAndPort("1.1.1.1", 3389))
        .onTargetService(TargetService.RDP)
        .withQuitCrackingAfterOneFound()
        .usingUsernamePasswordPair(ImmutableList.of(CRED1, CRED2));

    assertThat(client.buildRunCommandArgs())
        .containsExactly(
            hydraFile.getAbsolutePath(),
            "-C",
            creds.getAbsolutePath(),
            "-F",
            "-o",
            report.getAbsolutePath(),
            "rdp://1.1.1.1:3389");
  }

  @Test
  public void buildRunCommandArgs_withCustomParallelConnects_returnsCorrectCommandLine() {
    clioptions = new HydraClientCliOptions();
    clioptions.parallelConnects = 6;
    client = new HydraClient(hydraFile.getAbsolutePath(), true, creds, report, clioptions);
    client
        .withNetworkEndpoint(forIpAndPort("1.1.1.1", 3389))
        .onTargetService(TargetService.RDP)
        .usingUsernamePasswordPair(ImmutableList.of(CRED1, CRED2));

    assertThat(client.buildRunCommandArgs())
        .containsExactly(
            hydraFile.getAbsolutePath(),
            "-C",
            creds.getAbsolutePath(),
            "-t",
            "6",
            "-o",
            report.getAbsolutePath(),
            "rdp://1.1.1.1:3389");
  }

  @Test
  public void getResults_onceClientHasRan_returnsDetectedCredentials()
      throws IOException, ExecutionException, InterruptedException {
    try (BufferedWriter writer =
        Files.newBufferedWriter(report.toPath(), Charset.defaultCharset())) {
      writer.write("[3389][rdp] host: 1.1.1.1   login: root   password: toor");
    }
    Process process = mock(Process.class, RETURNS_SMART_NULLS);
    when(process.onExit()).thenReturn(CompletableFuture.completedFuture(process));
    when(commandExecutor.executeAsync()).thenReturn(process);

    HydraRun results =
        client
            .withNetworkEndpoint(forIp("1.1.1.1"))
            .onTargetService(TargetService.RDP)
            .usingUsernamePasswordPair(ImmutableList.of(CRED1, CRED2))
            .run();

    assertThat(results.discoveredCredentials())
        .containsExactly(
            DiscoveredCredential.builder()
                .setNetworkEndpoint(forIpAndPort("1.1.1.1", 3389))
                .setService("rdp")
                .setUsername("root")
                .setPassword("toor")
                .build());
    String data = Files.readString(creds.toPath());
    assertThat(data).isEqualTo("root:toor\nadmin:password\n");
  }

  @Test
  public void getTargetService_withService_returnsProvidedService() {
    client
        .withNetworkEndpoint(forIp("1.1.1.1"))
        .onTargetService(TargetService.RDP)
        .usingUsernamePasswordPair(ImmutableList.of(CRED1, CRED2));

    assertThat(client.getTargetService()).isEqualTo(TargetService.RDP);
  }

  @Test
  public void getEnableHydra_withNotEnableHydra_returnsProvidedEnableHydra() throws IOException {
    client = new HydraClient(hydraFile.getAbsolutePath(), false, creds, report, clioptions);
    client
        .withNetworkEndpoint(forIp("1.1.1.1"))
        .onTargetService(TargetService.RDP)
        .usingUsernamePasswordPair(ImmutableList.of(CRED1, CRED2));

    assertThat(client.isEnableHydra()).isFalse();
  }
}
