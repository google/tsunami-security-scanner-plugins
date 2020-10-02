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
package com.google.tsunami.plugins.portscan.nmap.client;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.RETURNS_SMART_NULLS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.google.tsunami.common.command.CommandExecutor;
import com.google.tsunami.common.command.CommandExecutorFactory;
import com.google.tsunami.common.data.NetworkEndpointUtils;
import com.google.tsunami.plugins.portscan.nmap.client.NmapClient.DnsResolution;
import com.google.tsunami.plugins.portscan.nmap.client.NmapClient.HostDiscoveryTechnique;
import com.google.tsunami.plugins.portscan.nmap.client.NmapClient.ScanTechnique;
import com.google.tsunami.plugins.portscan.nmap.client.NmapClient.TimingTemplate;
import com.google.tsunami.plugins.portscan.nmap.client.result.NmapRun;
import com.google.tsunami.proto.TransportProtocol;
import java.io.BufferedWriter;
import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import javax.xml.parsers.ParserConfigurationException;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.xml.sax.SAXException;

/** Tests for {@link NmapClient}. */
@RunWith(JUnit4.class)
public class NmapClientTest {

  @Rule public TemporaryFolder tempFolder = new TemporaryFolder();
  private File nmapFile;
  private File report;
  private NmapClient client;
  @Mock CommandExecutor commandExecutor;

  @Before
  public void setup() throws IOException {
    MockitoAnnotations.initMocks(this);
    CommandExecutorFactory.setInstance(commandExecutor);
    nmapFile = tempFolder.newFile("nmap");
    report = tempFolder.newFile("report");
    client = new NmapClient(nmapFile.getAbsolutePath(), report);
  }

  @Test
  public void newClient_whenNmapClientDoesNotExist_throwsException() {
    assertThrows(
        IllegalArgumentException.class,
        () -> new NmapClient("fileNotExist", tempFolder.newFile("faleReport")));
  }

  @Test
  public void buildRunCommandArgs_Ipv4SynScan_returnsCorrectCommandLine() {
    client
        .withTargetNetworkEndpoint(NetworkEndpointUtils.forIp("1.1.1.1"))
        .withHostDiscoveryTechnique(HostDiscoveryTechnique.SYN)
        .withScanTechnique(ScanTechnique.SYN);

    assertThat(client.buildRunCommandArgs())
        .containsExactly(
            nmapFile.getAbsolutePath(), "-PS", "-sS", "1.1.1.1", "-oX", report.getAbsolutePath());
  }

  @Test
  public void buildRunCommandArgs_multipleTargets_returnsCorrectCommandLine() {
    client
        .withTargetNetworkEndpoint(NetworkEndpointUtils.forIp("1.1.1.1"))
        .withTargetNetworkEndpoint(NetworkEndpointUtils.forIp("1.1.1.2"))
        .withHostDiscoveryTechnique(HostDiscoveryTechnique.SYN)
        .withScanTechnique(ScanTechnique.SYN);

    assertThat(client.buildRunCommandArgs())
        .containsExactly(
            nmapFile.getAbsolutePath(),
            "-PS",
            "-sS",
            "1.1.1.1",
            "1.1.1.2",
            "-oX",
            report.getAbsolutePath());
  }

  @Test
  public void buildRunCommandArgs_withIpv6AndTreatAllHostsAsOnline_returnsCorrectCommandLine() {
    client
        .withTargetNetworkEndpoint(NetworkEndpointUtils.forIp("2001:4860:4860::8844"))
        .treatAllHostsAsOnline();

    assertThat(client.buildRunCommandArgs())
        .containsExactly(
            nmapFile.getAbsolutePath(),
            "-Pn",
            "-6",
            "2001:4860:4860::8844",
            "-oX",
            report.getAbsolutePath());
  }

  @Test
  public void buildRunCommandArgs_withIpv4AndIpv6_returnsCorrectCommandLine() {
    client
        .withTargetNetworkEndpoint(NetworkEndpointUtils.forIp("2001:4860:4860::8844"))
        .withTargetNetworkEndpoint(NetworkEndpointUtils.forIp("1.1.1.1"))
        .treatAllHostsAsOnline();

    assertThat(client.buildRunCommandArgs())
        .containsExactly(
            nmapFile.getAbsolutePath(),
            "-Pn",
            "-6",
            "2001:4860:4860::8844",
            "1.1.1.1",
            "-oX",
            report.getAbsolutePath());
  }

  @Test
  public void buildRunCommandArgs_withServiceDiscoveryOnPort80_returnsCorrectCommandLine() {
    client
        .withTargetNetworkEndpoint(NetworkEndpointUtils.forIp("1.1.1.1"))
        .withServiceAndVersionDetection()
        .onPort(80, TransportProtocol.TRANSPORT_PROTOCOL_UNSPECIFIED);

    assertThat(client.buildRunCommandArgs())
        .containsExactly(
            nmapFile.getAbsolutePath(),
            "-p",
            "80",
            "-sV",
            "1.1.1.1",
            "-oX",
            report.getAbsolutePath());
  }

  @Test
  public void buildRunCommandArgs_withServiceDiscoveryOnPortRange_returnsCorrectCommandLine() {
    client
        .withTargetNetworkEndpoint(NetworkEndpointUtils.forIp("1.1.1.1"))
        .withServiceAndVersionDetection()
        .onPortRange(0, 1024, TransportProtocol.TRANSPORT_PROTOCOL_UNSPECIFIED);

    assertThat(client.buildRunCommandArgs())
        .containsExactly(
            nmapFile.getAbsolutePath(),
            "-p",
            "0-1024",
            "-sV",
            "1.1.1.1",
            "-oX",
            report.getAbsolutePath());
  }

  @Test
  public void buildRunCommandArgs_withServiceDiscoveryOnSeveralPorts_returnsCorrectCommandLine() {
    client
        .withTargetNetworkEndpoint(NetworkEndpointUtils.forIp("1.1.1.1"))
        .withServiceAndVersionDetection()
        .onPortRange(0, 1024, TransportProtocol.TRANSPORT_PROTOCOL_UNSPECIFIED)
        .onPort(8080, TransportProtocol.TRANSPORT_PROTOCOL_UNSPECIFIED)
        .onPort(8081, TransportProtocol.TRANSPORT_PROTOCOL_UNSPECIFIED);

    assertThat(client.buildRunCommandArgs())
        .containsExactly(
            nmapFile.getAbsolutePath(),
            "-p",
            "0-1024,8080,8081",
            "-sV",
            "1.1.1.1",
            "-oX",
            report.getAbsolutePath());
  }

  @Test
  public void buildRunCommandArgs_whenPortsHaveDifferentProtocols_returnsCorrectCommandLine() {
    client
        .withTargetNetworkEndpoint(NetworkEndpointUtils.forIp("1.1.1.1"))
        .withServiceAndVersionDetection()
        .onPortRange(0, 1024, TransportProtocol.TCP)
        .onPort(8080, TransportProtocol.UDP)
        .onPort(8081, TransportProtocol.TRANSPORT_PROTOCOL_UNSPECIFIED);

    assertThat(client.buildRunCommandArgs())
        .containsExactly(
            nmapFile.getAbsolutePath(),
            "-p",
            "8081,T:0-1024,U:8080",
            "-sV",
            "1.1.1.1",
            "-oX",
            report.getAbsolutePath());
  }

  @Test
  public void buildRunCommandArgs_withServiceDiscoveryAndIntensity_returnsCorrectCommandLine() {
    client
        .withTargetNetworkEndpoint(NetworkEndpointUtils.forIp("1.1.1.1"))
        .withServiceAndVersionDetection()
        .withVersionDetectionIntensity(4);

    assertThat(client.buildRunCommandArgs())
        .containsExactly(
            nmapFile.getAbsolutePath(),
            "-sV",
            "--version-intensity",
            "4",
            "1.1.1.1",
            "-oX",
            report.getAbsolutePath());
  }

  @Test
  public void buildRunCommandArgs_asPrivileged_returnsCorrectCommandLine() {
    client.withTargetNetworkEndpoint(NetworkEndpointUtils.forIp("1.1.1.1")).asPrivileged();

    assertThat(client.buildRunCommandArgs())
        .containsExactly(
            nmapFile.getAbsolutePath(), "--privileged", "1.1.1.1", "-oX", report.getAbsolutePath());
  }

  @Test
  public void buildRunCommandArgs_asUnprivileged_returnsCorrectCommandLine() {
    client.withTargetNetworkEndpoint(NetworkEndpointUtils.forIp("1.1.1.1")).asUnprivileged();

    assertThat(client.buildRunCommandArgs())
        .containsExactly(
            nmapFile.getAbsolutePath(),
            "--unprivileged",
            "1.1.1.1",
            "-oX",
            report.getAbsolutePath());
  }

  @Test
  public void buildRunCommandArgs_withDnsResolutionOnCustomServer_returnsCorrectCommandLine() {
    client
        .withTargetNetworkEndpoint(NetworkEndpointUtils.forIp("1.1.1.1"))
        .withDnsResolution(DnsResolution.ALWAYS)
        .resolveWithDnsServer("8.8.8.8", "8.8.4.4");

    assertThat(client.buildRunCommandArgs())
        .containsExactly(
            nmapFile.getAbsolutePath(),
            "-R",
            "--dns-servers",
            "8.8.8.8,8.8.4.4",
            "1.1.1.1",
            "-oX",
            report.getAbsolutePath());
  }

  @Test
  public void buildRunCommandArgs_withTraceroute_returnsCorrectCommandLine() {
    client.withTargetNetworkEndpoint(NetworkEndpointUtils.forIp("1.1.1.1")).withTraceroute();

    assertThat(client.buildRunCommandArgs())
        .containsExactly(
            nmapFile.getAbsolutePath(), "--traceroute", "1.1.1.1", "-oX", report.getAbsolutePath());
  }

  @Test
  public void buildRunCommandArgs_withFastScan_returnsCorrectCommandLine() throws IOException {
    client.withTargetNetworkEndpoint(NetworkEndpointUtils.forIp("1.1.1.1")).withFastScanMode();

    assertThat(client.buildRunCommandArgs())
        .containsExactly(
            nmapFile.getAbsolutePath(), "-F", "1.1.1.1", "-oX", report.getAbsolutePath());
  }

  @Test
  public void buildRunCommandArgs_withOsDetection_returnsCorrectCommandLine() {
    client.withTargetNetworkEndpoint(NetworkEndpointUtils.forIp("1.1.1.1")).withOsDetection();

    assertThat(client.buildRunCommandArgs())
        .containsExactly(
            nmapFile.getAbsolutePath(), "-O", "1.1.1.1", "-oX", report.getAbsolutePath());
  }

  @Test
  public void buildRunCommandArgs_withTimingTemplate_returnsCorrectCommandLine() {
    client
        .withTargetNetworkEndpoint(NetworkEndpointUtils.forIp("1.1.1.1"))
        .withTimingTemplate(TimingTemplate.INSANE);

    assertThat(client.buildRunCommandArgs())
        .containsExactly(
            nmapFile.getAbsolutePath(), "-T5", "1.1.1.1", "-oX", report.getAbsolutePath());
  }

  @Test
  public void buildRunCommandArgs_withScript_returnsCorrectCommandLine() throws IOException {
    client
        .withTargetNetworkEndpoint(NetworkEndpointUtils.forIp("1.1.1.1"))
        .withScript("test", "a", "b");

    assertThat(client.buildRunCommandArgs())
        .containsExactly(
            nmapFile.getAbsolutePath(),
            "--script",
            "test",
            "--script-args",
            "a,b",
            "1.1.1.1",
            "-oX",
            report.getAbsolutePath());
  }

  @Test
  public void buildRunCommandArgs_withMultipleScript_returnsCorrectCommandLine() {
    client
        .withTargetNetworkEndpoint(NetworkEndpointUtils.forIp("1.1.1.1"))
        .withScript("test1", "a", "b")
        .withScript("test2", "e", "f");

    assertThat(client.buildRunCommandArgs())
        .containsExactly(
            nmapFile.getAbsolutePath(),
            "--script",
            "test1",
            "--script-args",
            "a,b",
            "--script",
            "test2",
            "--script-args",
            "e,f",
            "1.1.1.1",
            "-oX",
            report.getAbsolutePath());
  }

  @Test
  public void getResults_onceClientHasRan_returnsNmapRunReport()
      throws IOException, ExecutionException, InterruptedException, ParserConfigurationException,
          SAXException {
    try (BufferedWriter writer =
        Files.newBufferedWriter(report.toPath(), Charset.defaultCharset())) {
      writer.write(
          "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
              + "<!DOCTYPE nmaprun>\n"
              + "<?xml-stylesheet href=\"file:///usr/bin/../share/nmap/nmap.xsl\""
              + " type=\"text/xsl\"?>\n"
              + "<nmaprun scanner=\"nmap\"\n"
              + "    args=\"nmap -n -sS -Pn -O -&#45;version-intensity 9 -sC -sV -6 -oX"
              + " /tmp/ipv6.xml 2001:4860:4860::8888\"\n"
              + "    start=\"1573478646\" startstr=\"Mon Nov 11 14:24:06 2019\" version=\"7.70\"\n"
              + "    xmloutputversion=\"1.04\">\n"
              + " <verbose level=\"0\"/>\n"
              + " <debugging level=\"0\"/>\n"
              + " <runstats>\n"
              + "  <finished time=\"1573478879\" elapsed=\"232.81\"/>\n"
              + "  <hosts up=\"1\" down=\"0\" total=\"1\"/>\n"
              + " </runstats>\n"
              + "</nmaprun>\n");
    }
    Process process = mock(Process.class, RETURNS_SMART_NULLS);
    when(commandExecutor.execute(any())).thenReturn(process);

    NmapRun results =
        client
            .withTargetNetworkEndpoint(NetworkEndpointUtils.forIp("1.1.1.1"))
            .withHostDiscoveryTechnique(HostDiscoveryTechnique.SYN)
            .withScanTechnique(ScanTechnique.SYN)
            .run(Executors.newCachedThreadPool());

    assertThat(results).isNotNull();
  }
}
