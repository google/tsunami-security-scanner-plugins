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
package com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.clients.ncrack;

import static com.google.common.truth.Truth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forIp;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forIpAndPort;
import static org.junit.Assert.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.RETURNS_SMART_NULLS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ListMultimap;
import com.google.tsunami.common.command.CommandExecutor;
import com.google.tsunami.common.command.CommandExecutorFactory;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.clients.common.DiscoveredCredential;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.clients.ncrack.NcrackClient.NcrackClientCliOptions;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.clients.ncrack.NcrackClient.TimingTemplate;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.clients.ncrack.data.NcrackRun;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.proto.TargetService;
import java.io.BufferedWriter;
import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

/** Tests for {@link NcrackClient}. */
@RunWith(JUnit4.class)
public class NcrackClientTest {

  @Rule public TemporaryFolder tempFolder = new TemporaryFolder();
  private File ncrackFile;
  private File report;
  private NcrackClient client;
  private NcrackClientCliOptions clioptions;

  @Mock CommandExecutor commandExecutor;

  @Before
  public void setup() throws IOException {
    MockitoAnnotations.initMocks(this);
    CommandExecutorFactory.setInstance(commandExecutor);
    ncrackFile = tempFolder.newFile("ncrack");
    report = tempFolder.newFile("report");
    clioptions = new NcrackClientCliOptions();
    client = new NcrackClient(ncrackFile.getAbsolutePath(), report, clioptions);
  }

  @Test
  public void newClient_whenNcrackClientDoesNotExist_throwsException() throws IOException {
    assertThrows(
        IllegalArgumentException.class,
        () -> new NcrackClient("fileNotExist", tempFolder.newFile("fakeReport"), null));
  }

  @Test
  public void buildRunCommandArgs_withIpv4TargetAndSshService_returnsCorrectCommandLine() {

    client
        .withNetworkEndpoint(forIp("1.1.1.1"))
        .onTargetService(TargetService.SSH)
        .usingUsernameList(ImmutableList.of("root", "admin"))
        .usingPasswordList(ImmutableList.of("toor", "password"));

    assertThat(client.buildRunCommandArgs())
        .containsExactly(
            ncrackFile.getAbsolutePath(),
            "--user",
            "root,admin",
            "--pass",
            "toor,password",
            "ssh://1.1.1.1",
            "-oN",
            report.getAbsolutePath());
  }

  @Test
  public void buildRunCommandArgs_withIpv6TargetAndSshService_returnsCorrectCommandLine() {
    client
        .withNetworkEndpoint(forIp("2001:4860:4860::8844"))
        .onTargetService(TargetService.SSH)
        .usingUsernameList(ImmutableList.of("root", "admin"))
        .usingPasswordList(ImmutableList.of("toor", "password"));

    assertThat(client.buildRunCommandArgs())
        .containsExactly(
            ncrackFile.getAbsolutePath(),
            "--user",
            "root,admin",
            "--pass",
            "toor,password",
            "-6",
            "ssh://[2001:4860:4860::8844]",
            "-oN",
            report.getAbsolutePath());
  }

  @Test
  public void buildRunCommandArgs_withMultipleTargetsAndSshService_returnsCorrectCommandLine() {
    client
        .withNetworkEndpoint(forIp("1.1.1.1"))
        .withNetworkEndpoint(forIp("1.1.1.2"))
        .onTargetService(TargetService.SSH)
        .usingUsernameList(ImmutableList.of("root", "admin"))
        .usingPasswordList(ImmutableList.of("toor", "password"));

    assertThat(client.buildRunCommandArgs())
        .containsExactly(
            ncrackFile.getAbsolutePath(),
            "--user",
            "root,admin",
            "--pass",
            "toor,password",
            "ssh://1.1.1.1",
            "ssh://1.1.1.2",
            "-oN",
            report.getAbsolutePath());
  }

  @Test
  public void buildRunCommandArgs_withPathAndSslEnabled_returnsCorrectCommandLine() {
    client
        .withNetworkEndpoint(forIp("1.1.1.1"))
        .onTargetService(TargetService.WORDPRESS)
        .withSslEnabled()
        .onPath("/blog/wp-login.php")
        .usingUsernameList(ImmutableList.of("root", "admin"))
        .usingPasswordList(ImmutableList.of("toor", "password"));

    assertThat(client.buildRunCommandArgs())
        .containsExactly(
            ncrackFile.getAbsolutePath(),
            "--user",
            "root,admin",
            "--pass",
            "toor,password",
            "wordpress://1.1.1.1,path=/blog/wp-login.php,ssl",
            "-oN",
            report.getAbsolutePath());
  }

  @Test
  public void buildRunCommandArgs_withDb_returnsCorrectCommandLine() throws IOException {
    client
        .withNetworkEndpoint(forIp("1.1.1.1"))
        .onTargetService(TargetService.MONGODB)
        .onDb("sales")
        .usingUsernameList(ImmutableList.of("root", "admin"))
        .usingPasswordList(ImmutableList.of("toor", "password"));

    assertThat(client.buildRunCommandArgs())
        .containsExactly(
            ncrackFile.getAbsolutePath(),
            "--user",
            "root,admin",
            "--pass",
            "toor,password",
            "mongodb://1.1.1.1,db=sales",
            "-oN",
            report.getAbsolutePath());
  }

  @Test
  public void buildRunCommandArgs_withDomain_returnsCorrectCommandLine() {
    client
        .withNetworkEndpoint(forIp("1.1.1.1"))
        .onTargetService(TargetService.WINRM)
        .onDomain("ActiveDirectory")
        .usingUsernameList(ImmutableList.of("root", "admin"))
        .usingPasswordList(ImmutableList.of("toor", "password"));

    assertThat(client.buildRunCommandArgs())
        .containsExactly(
            ncrackFile.getAbsolutePath(),
            "--user",
            "root,admin",
            "--pass",
            "toor,password",
            "winrm://1.1.1.1,domain=ActiveDirectory",
            "-oN",
            report.getAbsolutePath());
  }

  @Test
  public void buildRunCommandArgs_withUsernamePassPair_returnsCorrectCommandLine() {
    ListMultimap<String, String> credentials = ArrayListMultimap.create();
    credentials.put("root", "toor");
    credentials.put("root", "password");

    client
        .withNetworkEndpoint(forIp("1.1.1.1"))
        .onTargetService(TargetService.SSH)
        .usingUsernamePasswordPair(credentials);

    assertThat(client.buildRunCommandArgs())
        .containsExactly(
            ncrackFile.getAbsolutePath(),
            "--user",
            "root,root",
            "--pass",
            "toor,password",
            "--pairwise",
            "ssh://1.1.1.1",
            "-oN",
            report.getAbsolutePath());
  }

  @Test
  public void buildRunCommandArgs_withCustomPort_returnsCorrectCommandLine() {

    client
        .withNetworkEndpoint(forIpAndPort("1.1.1.1", 2222))
        .onTargetService(TargetService.SSH)
        .usingUsernameList(ImmutableList.of("root", "admin"))
        .usingPasswordList(ImmutableList.of("toor", "password"));

    assertThat(client.buildRunCommandArgs())
        .containsExactly(
            ncrackFile.getAbsolutePath(),
            "--user",
            "root,admin",
            "--pass",
            "toor,password",
            "ssh://1.1.1.1:2222",
            "-oN",
            report.getAbsolutePath());
  }

  @Test
  public void buildRunCommandArgs_withQuitCrackingAfterOneFound_returnsCorrectCommandLine() {
    client
        .withNetworkEndpoint(forIp("1.1.1.1"))
        .onTargetService(TargetService.SSH)
        .withQuitCrackingAfterOneFound()
        .usingUsernameList(ImmutableList.of("root", "admin"))
        .usingPasswordList(ImmutableList.of("toor", "password"));

    assertThat(client.buildRunCommandArgs())
        .containsExactly(
            ncrackFile.getAbsolutePath(),
            "--user",
            "root,admin",
            "--pass",
            "toor,password",
            "-f",
            "ssh://1.1.1.1",
            "-oN",
            report.getAbsolutePath());
  }

  @Test
  public void buildRunCommandArgs_withTimingTemplate_returnsCorrectCommandLine() {
    client
        .withNetworkEndpoint(forIp("1.1.1.1"))
        .onTargetService(TargetService.SSH)
        .withTimingTemplate(TimingTemplate.INSANE)
        .usingUsernameList(ImmutableList.of("root", "admin"))
        .usingPasswordList(ImmutableList.of("toor", "password"));

    assertThat(client.buildRunCommandArgs())
        .containsExactly(
            ncrackFile.getAbsolutePath(),
            "--user",
            "root,admin",
            "--pass",
            "toor,password",
            "-T5",
            "ssh://1.1.1.1",
            "-oN",
            report.getAbsolutePath());
  }

  @Test
  public void getResults_onceClientHasRan_returnsDetectedCredentials()
      throws IOException, ExecutionException, InterruptedException {
    try (BufferedWriter writer =
        Files.newBufferedWriter(report.toPath(), Charset.defaultCharset())) {
      writer.write("1.1.1.1 8888/tcp http: 'root' 'toor'");
    }
    Process process = mock(Process.class, RETURNS_SMART_NULLS);
    when(commandExecutor.execute(any())).thenReturn(process);

    NcrackRun results =
        client
            .withNetworkEndpoint(forIp("1.1.1.1"))
            .onTargetService(TargetService.SSH)
            .withTimingTemplate(TimingTemplate.INSANE)
            .usingUsernameList(ImmutableList.of("root", "admin"))
            .usingPasswordList(ImmutableList.of("toor", "password"))
            .run(Executors.newCachedThreadPool());

    assertThat(results.discoveredCredentials())
        .containsExactly(
            DiscoveredCredential.builder()
                .setNetworkEndpoint(forIpAndPort("1.1.1.1", 8888))
                .setService("http")
                .setUsername("root")
                .setPassword("toor")
                .build());
  }

  @Test
  public void getTargets_withMultipleTargets_returnsProvidedTargets() {
    client
        .withNetworkEndpoint(forIp("1.1.1.1"))
        .withNetworkEndpoint(forIp("1.1.1.2"))
        .onTargetService(TargetService.SSH)
        .usingUsernameList(ImmutableList.of("root", "admin"))
        .usingPasswordList(ImmutableList.of("toor", "password"));

    assertThat(client.getNetworkEndpoints()).containsExactly(forIp("1.1.1.1"), forIp("1.1.1.2"));
  }

  @Test
  public void getTargetService_withService_returnsProvidedService() {
    client
        .withNetworkEndpoint(forIp("1.1.1.1"))
        .withNetworkEndpoint(forIp("1.1.1.2"))
        .onTargetService(TargetService.SSH)
        .usingUsernameList(ImmutableList.of("root", "admin"))
        .usingPasswordList(ImmutableList.of("toor", "password"));

    assertThat(client.getTargetService()).isEqualTo(TargetService.SSH);
  }

  @Test
  public void getUsernameList_withUsernameArgument_returnsProvidedUsernames() {
    client
        .withNetworkEndpoint(forIp("1.1.1.1"))
        .withNetworkEndpoint(forIp("1.1.1.2"))
        .onTargetService(TargetService.SSH)
        .usingUsernameList(ImmutableList.of("root", "admin"))
        .usingPasswordList(ImmutableList.of("toor", "password"));

    assertThat(client.getUsernameList()).containsExactly("root", "admin");
  }

  @Test
  public void getpasswordList_withpasswordArgument_returnsProvidedpasswords() {
    client
        .withNetworkEndpoint(forIp("1.1.1.1"))
        .withNetworkEndpoint(forIp("1.1.1.2"))
        .onTargetService(TargetService.SSH)
        .usingUsernameList(ImmutableList.of("root", "admin"))
        .usingPasswordList(ImmutableList.of("toor", "password"));

    assertThat(client.getPasswordList()).containsExactly("toor", "password");
  }

  @Test
  public void buildRunCommandArgs_withNCrackMaxTime_containsParameter() {
    clioptions = new NcrackClientCliOptions();
    client = new NcrackClient(ncrackFile.getAbsolutePath(), report, clioptions.withMaxTime("15m"));
    client
        .withNetworkEndpoint(forIp("1.1.1.1"))
        .onTargetService(TargetService.SSH)
        .withTimingTemplate(TimingTemplate.INSANE)
        .usingUsernameList(ImmutableList.of("root", "admin"))
        .usingPasswordList(ImmutableList.of("toor", "password"));

    assertThat(client.buildRunCommandArgs())
        .containsExactly(
            ncrackFile.getAbsolutePath(),
            "--user",
            "root,admin",
            "--pass",
            "toor,password",
            "-T5",
            "ssh://1.1.1.1",
            "-g to=15m",
            "-oN",
            report.getAbsolutePath());
  }
}
