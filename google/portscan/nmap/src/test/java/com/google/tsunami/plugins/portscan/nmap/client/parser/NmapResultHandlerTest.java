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

import com.google.tsunami.plugins.portscan.nmap.client.result.Address;
import com.google.tsunami.plugins.portscan.nmap.client.result.Cpe;
import com.google.tsunami.plugins.portscan.nmap.client.result.Debugging;
import com.google.tsunami.plugins.portscan.nmap.client.result.Distance;
import com.google.tsunami.plugins.portscan.nmap.client.result.Elem;
import com.google.tsunami.plugins.portscan.nmap.client.result.ExtraPorts;
import com.google.tsunami.plugins.portscan.nmap.client.result.ExtraReasons;
import com.google.tsunami.plugins.portscan.nmap.client.result.Finished;
import com.google.tsunami.plugins.portscan.nmap.client.result.Hop;
import com.google.tsunami.plugins.portscan.nmap.client.result.Host;
import com.google.tsunami.plugins.portscan.nmap.client.result.HostScript;
import com.google.tsunami.plugins.portscan.nmap.client.result.Hostname;
import com.google.tsunami.plugins.portscan.nmap.client.result.Hostnames;
import com.google.tsunami.plugins.portscan.nmap.client.result.Hosts;
import com.google.tsunami.plugins.portscan.nmap.client.result.IpIdSequence;
import com.google.tsunami.plugins.portscan.nmap.client.result.NmapRun;
import com.google.tsunami.plugins.portscan.nmap.client.result.Os;
import com.google.tsunami.plugins.portscan.nmap.client.result.OsClass;
import com.google.tsunami.plugins.portscan.nmap.client.result.OsFingerprint;
import com.google.tsunami.plugins.portscan.nmap.client.result.OsMatch;
import com.google.tsunami.plugins.portscan.nmap.client.result.Output;
import com.google.tsunami.plugins.portscan.nmap.client.result.Port;
import com.google.tsunami.plugins.portscan.nmap.client.result.PortUsed;
import com.google.tsunami.plugins.portscan.nmap.client.result.Ports;
import com.google.tsunami.plugins.portscan.nmap.client.result.PostScript;
import com.google.tsunami.plugins.portscan.nmap.client.result.PreScript;
import com.google.tsunami.plugins.portscan.nmap.client.result.RunStats;
import com.google.tsunami.plugins.portscan.nmap.client.result.ScanInfo;
import com.google.tsunami.plugins.portscan.nmap.client.result.Script;
import com.google.tsunami.plugins.portscan.nmap.client.result.Service;
import com.google.tsunami.plugins.portscan.nmap.client.result.Smurf;
import com.google.tsunami.plugins.portscan.nmap.client.result.State;
import com.google.tsunami.plugins.portscan.nmap.client.result.Status;
import com.google.tsunami.plugins.portscan.nmap.client.result.Table;
import com.google.tsunami.plugins.portscan.nmap.client.result.Target;
import com.google.tsunami.plugins.portscan.nmap.client.result.TaskBegin;
import com.google.tsunami.plugins.portscan.nmap.client.result.TaskEnd;
import com.google.tsunami.plugins.portscan.nmap.client.result.TaskProgress;
import com.google.tsunami.plugins.portscan.nmap.client.result.TcpSequence;
import com.google.tsunami.plugins.portscan.nmap.client.result.TcpTsSequence;
import com.google.tsunami.plugins.portscan.nmap.client.result.Times;
import com.google.tsunami.plugins.portscan.nmap.client.result.Trace;
import com.google.tsunami.plugins.portscan.nmap.client.result.Uptime;
import com.google.tsunami.plugins.portscan.nmap.client.result.Verbose;
import java.io.IOException;
import java.io.InputStream;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.xml.sax.SAXException;

/** Tests for {@link NmapResultHandler}. */
@RunWith(JUnit4.class)
public final class NmapResultHandlerTest {
  private SAXParser parser;

  @Before
  public void setUp() throws ParserConfigurationException, SAXException {
    parser = SAXParserFactory.newInstance().newSAXParser();
  }

  @Test
  public void parse_always_buildsNmapRunFromXmlDocument() throws IOException, SAXException {
    InputStream resource = getClass().getResourceAsStream("testdata/scanRunIPv6.xml");
    NmapResultHandler nmapResultHandler = new NmapResultHandler();

    parser.parse(resource, nmapResultHandler);

    assertThat(nmapResultHandler.getNmapRun())
        .isEqualTo(
            NmapRun.builder()
                .setScanner("nmap")
                .setArgs(
                    "nmap -n -sS -Pn -O --version-intensity 9 -sC -sV -6 -oX /tmp/ipv6.xml"
                        + " 2001:4860:4860::8888")
                .setStart("1573478646")
                .setStartStr("Mon Nov 11 14:24:06 2019")
                .setVersion("7.70")
                .setProfileName("")
                .setXmlOutputVersion("1.04")
                .setVerbose(Verbose.builder().setLevel("0").build())
                .setDebugging(Debugging.builder().setLevel("0").build())
                .addValueElement(
                    Target.builder()
                        .setSpecification("test specification")
                        .setStatus("skipped")
                        .setReason("invalid")
                        .build())
                .addValueElement(
                    TaskBegin.builder()
                        .setTask("test task")
                        .setTime("123456789")
                        .setExtraInfo("test extrainfo")
                        .build())
                .addValueElement(
                    TaskProgress.builder()
                        .setTask("test task")
                        .setTime("123456789")
                        .setPercent("90")
                        .setRemaining("10")
                        .setEtc("123")
                        .build())
                .addValueElement(
                    TaskEnd.builder()
                        .setTask("test task")
                        .setTime("123456789")
                        .setExtraInfo("test extrainfo")
                        .build())
                .addValueElement(
                    PreScript.builder()
                        .addScript(
                            Script.builder()
                                .setId("test prescript script1 id")
                                .setOutput("test prescript script1 output")
                                .addValueElement(
                                    Elem.builder()
                                        .setKey("test prescript script1 elem key")
                                        .setValue(
                                            "\n        test prescript script1 elem value\n      ")
                                        .build())
                                .addValueElement("\n      \n    ")
                                .build())
                        .addScript(
                            Script.builder()
                                .setId("test prescript script2 id")
                                .setOutput("test prescript script2 output")
                                .addValueElement(
                                    Elem.builder()
                                        .setKey("test prescript script2 elem1 key")
                                        .setValue(
                                            "\n        test prescript script2 elem1 value\n      ")
                                        .build())
                                .addValueElement(
                                    Elem.builder()
                                        .setKey("test prescript script2 elem2 key")
                                        .setValue(
                                            "\n        test prescript script2 elem2 value\n      ")
                                        .build())
                                .addValueElement("\n      \n      \n    ")
                                .build())
                        .build())
                .addValueElement(
                    PostScript.builder()
                        .addScript(
                            Script.builder()
                                .setId("test postscript script id")
                                .setOutput("test postscript script output")
                                .addValueElement(
                                    Table.builder()
                                        .setKey("test postscript table key")
                                        .addValueElement(
                                            Elem.builder()
                                                .setKey("test postscript table elem key")
                                                .setValue(
                                                    "\n"
                                                        + "          test postscript table elem"
                                                        + " value\n"
                                                        + "        ")
                                                .build())
                                        .build())
                                .addValueElement(
                                    Table.builder()
                                        .setKey("test postscript nest outer table key")
                                        .addValueElement(
                                            Table.builder()
                                                .setKey("test postscript nest inner table key")
                                                .addValueElement(
                                                    Elem.builder()
                                                        .setKey(
                                                            "test postscript nest table elem key")
                                                        .setValue(
                                                            "\n"
                                                                + "            test postscript"
                                                                + " table elem value\n"
                                                                + "          ")
                                                        .build())
                                                .build())
                                        .build())
                                .addValueElement("\n      \n      \n    ")
                                .build())
                        .build())
                .addValueElement(
                    Host.builder()
                        .setStartTime("1573478646")
                        .setEndTime("1573478879")
                        .setComment("host comment")
                        .addValueElement(
                            Status.builder()
                                .setState("up")
                                .setReason("user-set")
                                .setReasonTtl("0")
                                .build())
                        .addValueElement(
                            Address.builder()
                                .setAddr("2001:4860:4860::8888")
                                .setAddrType("ipv6")
                                .setVendor("")
                                .build())
                        .addValueElement(
                            Hostnames.builder()
                                .addHostname(
                                    Hostname.builder().setName("hostname").setType("user").build())
                                .addHostname(
                                    Hostname.builder().setName("hostname2").setType("PTR").build())
                                .build())
                        .addValueElement(Smurf.builder().setResponses("responses").build())
                        .addValueElement(
                            Ports.builder()
                                .addExtraPorts(
                                    ExtraPorts.builder()
                                        .setState("filtered")
                                        .setCount("998")
                                        .addExtraReasons(
                                            ExtraReasons.builder()
                                                .setReason("no-responses")
                                                .setCount("996")
                                                .build())
                                        .addExtraReasons(
                                            ExtraReasons.builder()
                                                .setReason("admin-prohibiteds")
                                                .setCount("2")
                                                .build())
                                        .build())
                                .addPort(
                                    Port.builder()
                                        .setProtocol("tcp")
                                        .setPortId("53")
                                        .setState(
                                            State.builder()
                                                .setState("open")
                                                .setReason("syn-ack")
                                                .setReasonTtl("120")
                                                .setReasonIp("")
                                                .build())
                                        .setService(
                                            Service.builder()
                                                .setName("tcpwrapped")
                                                .setConf("8")
                                                .setMethod("probed")
                                                .setVersion("")
                                                .setProduct("")
                                                .setExtraInfo("")
                                                .setTunnel("")
                                                .setProto("")
                                                .setRpcNum("")
                                                .setLowVer("")
                                                .setHighVer("")
                                                .setHostname("")
                                                .setOsType("")
                                                .setDeviceType("")
                                                .setServiceFp("")
                                                .build())
                                        .build())
                                .addPort(
                                    Port.builder()
                                        .setProtocol("tcp")
                                        .setPortId("443")
                                        .setState(
                                            State.builder()
                                                .setState("open")
                                                .setReason("syn-ack")
                                                .setReasonTtl("120")
                                                .setReasonIp("")
                                                .build())
                                        .setService(
                                            Service.builder()
                                                .setName("https")
                                                .setConf("10")
                                                .setMethod("probed")
                                                .setVersion("")
                                                .setProduct("sffe")
                                                .setExtraInfo("")
                                                .setTunnel("ssl")
                                                .setProto("")
                                                .setRpcNum("")
                                                .setLowVer("")
                                                .setHighVer("")
                                                .setHostname("")
                                                .setOsType("")
                                                .setDeviceType("")
                                                .setServiceFp("servicefp")
                                                .build())
                                        .addScript(
                                            Script.builder()
                                                .setId("http-title")
                                                .setOutput("Error 400 (Bad Request)!!1")
                                                .addValueElement(
                                                    Elem.builder()
                                                        .setKey("title")
                                                        .setValue("Error 400 (Bad Request)!!1")
                                                        .build())
                                                .addValueElement("\n          \n        ")
                                                .build())
                                        .build())
                                .build())
                        .addValueElement(
                            Os.builder()
                                .addPortUsed(
                                    PortUsed.builder()
                                        .setState("open")
                                        .setProto("tcp")
                                        .setPortId("53")
                                        .build())
                                .addOsMatch(
                                    OsMatch.builder()
                                        .setName("name")
                                        .setAccuracy("accuracy")
                                        .setLine("line")
                                        .addOsClass(
                                            OsClass.builder()
                                                .setVendor("vendor0")
                                                .setOsGen("osgen0")
                                                .setType("type0")
                                                .setAccuracy("accuracy0")
                                                .setOsFamily("osfamily0")
                                                .addCpe(Cpe.builder().setValue("cpe0").build())
                                                .build())
                                        .addOsClass(
                                            OsClass.builder()
                                                .setVendor("vendor1")
                                                .setOsGen("osgen1")
                                                .setType("type1")
                                                .setAccuracy("accuracy1")
                                                .setOsFamily("osfamily1")
                                                .addCpe(Cpe.builder().setValue("cpe1").build())
                                                .build())
                                        .build())
                                .addOsFingerprint(
                                    OsFingerprint.builder().setFingerprint("fingerprint").build())
                                .build())
                        .addValueElement(Distance.builder().setValue("distance value").build())
                        .addValueElement(Uptime.builder().setSeconds("1").setLastBoot("2").build())
                        .addValueElement(
                            TcpSequence.builder()
                                .setIndex("0")
                                .setDifficulty("difficulty")
                                .setValues("values")
                                .build())
                        .addValueElement(
                            IpIdSequence.builder().setClazz("class").setValues("values").build())
                        .addValueElement(
                            TcpTsSequence.builder().setClazz("class").setValues("values").build())
                        .addValueElement(
                            HostScript.builder()
                                .addScript(
                                    Script.builder()
                                        .setId("hostscript script id")
                                        .setOutput("hostscript script output")
                                        .addValueElement(
                                            Elem.builder()
                                                .setKey("hostscript script elem key")
                                                .setValue("elem value")
                                                .build())
                                        .addValueElement("\n        \n      ")
                                        .build())
                                .build())
                        .addValueElement(
                            Trace.builder()
                                .setProto("proto")
                                .setPort("port")
                                .addHop(
                                    Hop.builder()
                                        .setTtl("ttl")
                                        .setRtt("rtt")
                                        .setIpAddr("ipaddr")
                                        .setHost("host")
                                        .build())
                                .build())
                        .addValueElement(
                            Times.builder()
                                .setSrtt("1112")
                                .setRttVar("450")
                                .setTo("100000")
                                .build())
                        .build())
                .addValueElement(
                    Output.builder().setType("test output type").setValue("output value").build())
                .setRunStats(
                    RunStats.builder()
                        .setFinished(
                            Finished.builder()
                                .setTime("1573478879")
                                .setTimeStr("Mon Nov 11 14:27:59 2019")
                                .setElapsed("232.81")
                                .setSummary(
                                    "Nmap done at Mon Nov 11 14:27:59 2019; 1 IP address (1 host"
                                        + " up) scanned in 232.81 seconds")
                                .setExit("success")
                                .setErrorMsg("")
                                .build())
                        .setHosts(Hosts.builder().setUp("1").setDown("0").setTotal("1").build())
                        .build())
                .addScanInfo(
                    ScanInfo.builder()
                        .setType("syn")
                        .setScanFlags("")
                        .setProtocol("tcp")
                        .setNumServices("1000")
                        .setServices("1,2,3,80,2725")
                        .build())
                .build());
  }
}
