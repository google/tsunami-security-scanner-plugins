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

import com.google.tsunami.plugins.portscan.nmap.client.result.Host;
import com.google.tsunami.plugins.portscan.nmap.client.result.NmapRun;
import java.io.IOException;
import java.io.InputStream;
import javax.xml.parsers.ParserConfigurationException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.xml.sax.SAXException;

/** Tests for {@link XMLParser}. */
@RunWith(JUnit4.class)
public class XMLParserTest {

  @Test
  public void parse_always_extractsScanRunInfo()
      throws IOException, SAXException, ParserConfigurationException {
    InputStream resource = getClass().getResourceAsStream("testdata/scanRunIPv6.xml");

    NmapRun result = XMLParser.parse(resource);

    assertThat(result.scanner()).isEqualTo("nmap");
    assertThat(result.args())
        .isEqualTo(
            "nmap -n -sS -Pn -O --version-intensity 9 -sC -sV -6 -oX /tmp/ipv6.xml"
                + " 2001:4860:4860::8888");
    assertThat(result.start()).isEqualTo("1573478646");
    assertThat(result.scanInfos()).hasSize(1);
    assertThat(result.scanInfos().get(0).type()).isEqualTo("syn");
    assertThat(result.scanInfos().get(0).protocol()).isEqualTo("tcp");
    assertThat(result.scanInfos().get(0).services()).contains("2725");
  }

  @Test
  public void parse_always_extractsHost()
      throws IOException, SAXException, ParserConfigurationException {
    InputStream resource = getClass().getResourceAsStream("testdata/scanRunIPv6.xml");

    NmapRun result = XMLParser.parse(resource);

    assertThat(getHost(result)).isNotNull();
  }

  @Test
  public void parse_always_extractsHostStatus()
      throws IOException, SAXException, ParserConfigurationException {
    InputStream resource = getClass().getResourceAsStream("testdata/scanRunIPv6.xml");

    NmapRun result = XMLParser.parse(resource);

    Host host = getHost(result);
    assertThat(host).isNotNull();
    assertThat(host.statuses()).hasSize(1);
    assertThat(host.statuses().get(0).state()).isEqualTo("up");
  }

  @Test
  public void parse_always_extractsAddress()
      throws IOException, SAXException, ParserConfigurationException {
    InputStream resource = getClass().getResourceAsStream("testdata/scanRunIPv6.xml");

    NmapRun result = XMLParser.parse(resource);

    Host host = getHost(result);
    assertThat(host).isNotNull();
    assertThat(host.addresses()).hasSize(1);
    assertThat(host.addresses().get(0).addr()).isEqualTo("2001:4860:4860::8888");
    assertThat(host.addresses().get(0).addrType()).isEqualTo("ipv6");
    assertThat(host.addresses().get(0).vendor()).isEmpty();
  }

  @Test
  public void parse_always_extractsPorts()
      throws IOException, SAXException, ParserConfigurationException {
    InputStream resource = getClass().getResourceAsStream("testdata/scanRunIPv6.xml");

    NmapRun result = XMLParser.parse(resource);

    Host host = getHost(result);
    assertThat(host).isNotNull();
    assertThat(host.ports()).hasSize(1);
    assertThat(host.ports().get(0).ports()).hasSize(2);
    assertThat(host.ports().get(0).ports().get(0).portId()).isEqualTo("53");
    assertThat(host.ports().get(0).ports().get(0).protocol()).isEqualTo("tcp");
  }

  @Test
  public void parse_always_extractsPortService()
      throws IOException, SAXException, ParserConfigurationException {
    InputStream resource = getClass().getResourceAsStream("testdata/scanRunIPv6.xml");

    NmapRun result = XMLParser.parse(resource);

    Host host = getHost(result);
    assertThat(host).isNotNull();
    assertThat(host.ports().get(0).ports().get(1).service().name()).isEqualTo("https");
    assertThat(host.ports().get(0).ports().get(1).service().product()).isEqualTo("sffe");
    assertThat(host.ports().get(0).ports().get(1).service().tunnel()).isEqualTo("ssl");
  }

  @Test
  public void parse_always_extractsScriptOutput()
      throws IOException, SAXException, ParserConfigurationException {
    InputStream resource = getClass().getResourceAsStream("testdata/scanRunIPv6.xml");

    NmapRun result = XMLParser.parse(resource);

    Host host = getHost(result);
    assertThat(host).isNotNull();
    assertThat(host.ports().get(0).ports().get(1).scripts()).hasSize(1);
    assertThat(host.ports().get(0).ports().get(1).scripts().get(0).id()).isEqualTo("http-title");
    assertThat(host.ports().get(0).ports().get(1).scripts().get(0).output())
        .contains("Error 400 (Bad Request)!!1");
  }

  @Test
  public void parse_always_extractsActiveServiceInfo()
      throws IOException, SAXException, ParserConfigurationException {
    InputStream resource = getClass().getResourceAsStream("testdata/scanRunIPv6.xml");

    NmapRun result = XMLParser.parse(resource);

    Host host = getHost(result);
    assertThat(host).isNotNull();
    assertThat(host.oses()).hasSize(1);
    assertThat(host.oses().get(0).osFingerprints().get(0).fingerprint()).isEqualTo("fingerprint");
  }

  private static Host getHost(NmapRun nmapRun) {
    return nmapRun.hosts().stream().findFirst().orElse(null);
  }
}
