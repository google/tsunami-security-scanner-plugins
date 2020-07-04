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
package com.google.tsunami.plugins.portscan.nmap.client.parser;

import static com.google.common.truth.Truth.assertThat;

import com.google.common.collect.ImmutableList;
import com.google.tsunami.plugins.portscan.nmap.client.data.xml.Address;
import com.google.tsunami.plugins.portscan.nmap.client.data.xml.Host;
import com.google.tsunami.plugins.portscan.nmap.client.data.xml.Nmaprun;
import com.google.tsunami.plugins.portscan.nmap.client.data.xml.Os;
import com.google.tsunami.plugins.portscan.nmap.client.data.xml.Ports;
import com.google.tsunami.plugins.portscan.nmap.client.data.xml.Status;
import java.io.InputStream;
import java.util.List;
import javax.xml.bind.JAXBException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for {@link XMLParser}. */
@RunWith(JUnit4.class)
public class XMLParserTest {

  @Test
  public void parse_always_extractsScanRunInfo() throws JAXBException {
    InputStream resource = getClass().getResourceAsStream("testdata/scanRunIPv6.xml");

    Nmaprun result = XMLParser.parse(resource);

    assertThat(result.getScanner()).isEqualTo("nmap");
    assertThat(result.getArgs())
        .isEqualTo(
            "nmap -n -sS -Pn -O --version-intensity 9 -sC -sV -6 -oX /tmp/ipv6.xml"
                + " 2001:4860:4860::8888");
    assertThat(result.getStart()).isEqualTo("1573478646");
    assertThat(result.getScaninfo()).hasSize(1);
    assertThat(result.getScaninfo().get(0).getType()).isEqualTo("syn");
    assertThat(result.getScaninfo().get(0).getProtocol()).isEqualTo("tcp");
    assertThat(result.getScaninfo().get(0).getServices()).contains("2725");
  }

  @Test
  public void parse_always_extractsHost() throws JAXBException {
    InputStream resource = getClass().getResourceAsStream("testdata/scanRunIPv6.xml");

    Nmaprun result = XMLParser.parse(resource);

    assertThat(getHost(result)).isNotNull();
  }

  @Test
  public void parse_always_extractsHostStatus() throws JAXBException {
    InputStream resource = getClass().getResourceAsStream("testdata/scanRunIPv6.xml");

    Nmaprun result = XMLParser.parse(resource);

    Host host = getHost(result);
    List<Status> statuses =
        host
            .getStatusOrAddressOrHostnamesOrSmurfOrPortsOrOsOrDistanceOrUptimeOrTcpsequenceOrIpidsequenceOrTcptssequenceOrHostscriptOrTraceOrTimes()
            .stream()
            .filter(element -> element instanceof Status)
            .map(element -> (Status) element)
            .collect(ImmutableList.toImmutableList());
    assertThat(statuses).hasSize(1);
    assertThat(statuses.get(0).getState()).isEqualTo("up");
  }

  @Test
  public void parse_always_extractsAddress() throws JAXBException {
    InputStream resource = getClass().getResourceAsStream("testdata/scanRunIPv6.xml");

    Nmaprun result = XMLParser.parse(resource);

    Host host = getHost(result);
    List<Address> addresses =
        host
            .getStatusOrAddressOrHostnamesOrSmurfOrPortsOrOsOrDistanceOrUptimeOrTcpsequenceOrIpidsequenceOrTcptssequenceOrHostscriptOrTraceOrTimes()
            .stream()
            .filter(element -> element instanceof Address)
            .map(element -> (Address) element)
            .collect(ImmutableList.toImmutableList());

    assertThat(addresses).hasSize(1);
    assertThat(addresses.get(0).getAddr()).isEqualTo("2001:4860:4860::8888");
    assertThat(addresses.get(0).getAddrtype()).isEqualTo("ipv6");
    assertThat(addresses.get(0).getVendor()).isNull();
  }

  @Test
  public void parse_always_extractsPorts() throws JAXBException {
    InputStream resource = getClass().getResourceAsStream("testdata/scanRunIPv6.xml");

    Nmaprun result = XMLParser.parse(resource);

    Host host = getHost(result);
    List<Ports> ports =
        host
            .getStatusOrAddressOrHostnamesOrSmurfOrPortsOrOsOrDistanceOrUptimeOrTcpsequenceOrIpidsequenceOrTcptssequenceOrHostscriptOrTraceOrTimes()
            .stream()
            .filter(element -> element instanceof Ports)
            .map(element -> (Ports) element)
            .collect(ImmutableList.toImmutableList());
    assertThat(ports).hasSize(1);
    assertThat(ports.get(0).getPort()).hasSize(2);
    assertThat(ports.get(0).getPort().get(0).getPortid()).isEqualTo("53");
    assertThat(ports.get(0).getPort().get(0).getProtocol()).isEqualTo("tcp");
  }

  @Test
  public void parse_always_extractsPortService() throws JAXBException {
    InputStream resource = getClass().getResourceAsStream("testdata/scanRunIPv6.xml");

    Nmaprun result = XMLParser.parse(resource);

    Host host = getHost(result);
    List<Ports> ports =
        host
            .getStatusOrAddressOrHostnamesOrSmurfOrPortsOrOsOrDistanceOrUptimeOrTcpsequenceOrIpidsequenceOrTcptssequenceOrHostscriptOrTraceOrTimes()
            .stream()
            .filter(element -> element instanceof Ports)
            .map(element -> (Ports) element)
            .collect(ImmutableList.toImmutableList());
    assertThat(ports.get(0).getPort().get(1).getService().getName()).isEqualTo("https");
    assertThat(ports.get(0).getPort().get(1).getService().getProduct()).isEqualTo("sffe");
    assertThat(ports.get(0).getPort().get(1).getService().getTunnel()).isEqualTo("ssl");
  }

  @Test
  public void parse_always_extractsScriptOutput() throws JAXBException {
    InputStream resource = getClass().getResourceAsStream("testdata/scanRunIPv6.xml");

    Nmaprun result = XMLParser.parse(resource);

    Host host = getHost(result);
    List<Ports> ports =
        host
            .getStatusOrAddressOrHostnamesOrSmurfOrPortsOrOsOrDistanceOrUptimeOrTcpsequenceOrIpidsequenceOrTcptssequenceOrHostscriptOrTraceOrTimes()
            .stream()
            .filter(element -> element instanceof Ports)
            .map(element -> (Ports) element)
            .collect(ImmutableList.toImmutableList());
    assertThat(ports.get(0).getPort().get(1).getScript()).hasSize(4);
    assertThat(ports.get(0).getPort().get(1).getScript().get(0).getId())
        .isEqualTo("fingerprint-strings");
    assertThat(ports.get(0).getPort().get(1).getScript().get(0).getOutput()).contains("HTTP/1.0");
  }

  @Test
  public void parse_always_extractsActiveServiceInfo() throws JAXBException {
    InputStream resource = getClass().getResourceAsStream("testdata/scanRunIPv6.xml");

    Nmaprun result = XMLParser.parse(resource);

    Host host = getHost(result);
    List<Os> oses =
        host
            .getStatusOrAddressOrHostnamesOrSmurfOrPortsOrOsOrDistanceOrUptimeOrTcpsequenceOrIpidsequenceOrTcptssequenceOrHostscriptOrTraceOrTimes()
            .stream()
            .filter(element -> element instanceof Os)
            .map(element -> (Os) element)
            .collect(ImmutableList.toImmutableList());
    assertThat(oses).hasSize(1);
    assertThat(oses.get(0).getOsfingerprint().get(0).getFingerprint()).contains("linux-gnu");
  }

  private static Host getHost(Nmaprun nmaprun) {
    return nmaprun
        .getTargetOrTaskbeginOrTaskprogressOrTaskendOrPrescriptOrPostscriptOrHostOrOutput()
        .stream()
        .filter(obj -> obj instanceof Host)
        .map(obj -> (Host) obj)
        .findFirst()
        .orElse(null);
  }
}
