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

import static com.google.common.base.Preconditions.checkNotNull;

import com.google.auto.value.AutoValue;
import com.google.common.base.Joiner;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.common.flogger.GoogleLogger;
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
import com.google.tsunami.plugins.portscan.nmap.client.result.Owner;
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
import java.util.ArrayDeque;
import java.util.Arrays;
import org.checkerframework.checker.nullness.qual.Nullable;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

/**
 * Concrete implementation for a stack-based SAX {@link DefaultHandler} to parse Nmap XML scan
 * result.
 *
 * <p>The definition of the Nmap result XML can be found using the following link:
 * https://raw.githubusercontent.com/nmap/nmap/e7e7e9e8c7d83b4ca93a752dea7bb40cbb74df32/docs/nmap.dtd
 */
@SuppressWarnings("unused")
public final class NmapResultHandler extends DefaultHandler {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  private static final ImmutableSet<State> SCRIPT_ANCESTORS =
      ImmutableSet.of(
          State.IN_PRE_SCRIPT, State.IN_POST_SCRIPT, State.IN_HOST_SCRIPT, State.IN_PORT);
  private static final ImmutableSet<State> TABLE_ANCESTORS =
      ImmutableSet.of(State.IN_SCRIPT, State.IN_TABLE);
  private static final ImmutableSet<State> ELEM_ANCESTORS =
      ImmutableSet.of(State.IN_SCRIPT, State.IN_TABLE);
  private static final ImmutableSet<State> CPE_ANCESTORS =
      ImmutableSet.of(State.IN_SERVICE, State.IN_OS_CLASS);
  private static final String NMAP_RUN_ELEM = "nmaprun";
  private static final String SCAN_INFO_ELEM = "scaninfo";
  private static final String VERBOSE_ELEM = "verbose";
  private static final String DEBUGGING_ELEM = "debugging";
  private static final String TARGET_ELEM = "target";
  private static final String TASK_BEGIN_ELEM = "taskbegin";
  private static final String TASK_PROGRESS_ELEM = "taskprogress";
  private static final String TASK_END_ELEM = "taskend";
  private static final String PRE_SCRIPT_ELEM = "prescript";
  private static final String POST_SCRIPT_ELEM = "postscript";
  private static final String OUTPUT_ELEM = "output";
  private static final String HOST_ELEM = "host";
  private static final String RUN_STATS_ELEM = "runstats";
  private static final String FINISHED_ELEM = "finished";
  private static final String HOSTS_ELEM = "hosts";
  private static final String SCRIPT_ELEM = "script";
  private static final String CPE_ELEM = "cpe";
  private static final String TABLE_ELEM = "table";
  private static final String ELEM_ELEM = "elem";
  private static final String STATUS_ELEM = "status";
  private static final String ADDRESS_ELEM = "address";
  private static final String HOSTNAMES_ELEM = "hostnames";
  private static final String HOSTNAME_ELEM = "hostname";
  private static final String SMURF_ELEM = "smurf";
  private static final String PORTS_ELEM = "ports";
  private static final String OS_ELEM = "os";
  private static final String DISTANCE_ELEM = "distance";
  private static final String UPTIME_ELEM = "uptime";
  private static final String TCP_SEQUENCE_ELEM = "tcpsequence";
  private static final String IP_ID_SEQUENCE_ELEM = "ipidsequence";
  private static final String TCP_TS_SEQUENCE_ELEM = "tcptssequence";
  private static final String HOST_SCRIPT_ELEM = "hostscript";
  private static final String TRACE_ELEM = "trace";
  private static final String HOP_ELEM = "hop";
  private static final String TIMES_ELEM = "times";
  private static final String PORT_USED_ELEM = "portused";
  private static final String OS_MATCH_ELEM = "osmatch";
  private static final String OS_CLASS_ELEM = "osclass";
  private static final String OS_FINGERPRINT_ELEM = "osfingerprint";
  private static final String EXTRA_PORTS_ELEM = "extraports";
  private static final String EXTRA_REASONS_ELEM = "extrareasons";
  private static final String PORT_ELEM = "port";
  private static final String STATE_ELEM = "state";
  private static final String OWNER_ELEM = "owner";
  private static final String SERVICE_ELEM = "service";

  /** The stack maintaining the state for this parser. */
  private final ArrayDeque<SaxHandlerState> stateStack;

  private NmapRun.Builder nmapRunBuilder;
  private ScanInfo.Builder scanInfoBuilder;
  private Verbose.Builder verboseBuilder;
  private Debugging.Builder debuggingBuilder;
  private Target.Builder targetBuilder;
  private TaskBegin.Builder taskBeginBuilder;
  private TaskProgress.Builder taskProgressBuilder;
  private TaskEnd.Builder taskEndBuilder;
  private PreScript.Builder preScriptBuilder;
  private PostScript.Builder postScriptBuilder;
  private Host.Builder hostBuilder;
  private Output.Builder outputBuilder;
  private RunStats.Builder runStatsBuilder;
  private Finished.Builder finishedBuilder;
  private Hosts.Builder hostsBuilder;
  private Script.Builder scriptBuilder;
  private Cpe.Builder cpeBuilder;
  private ArrayDeque<Table.Builder> tableBuilderStack;
  private Elem.Builder elemBuilder;
  private Status.Builder statusBuilder;
  private Address.Builder addressBuilder;
  private Hostnames.Builder hostnamesBuilder;
  private Hostname.Builder hostnameBuilder;
  private Smurf.Builder smurfBuilder;
  private Ports.Builder portsBuilder;
  private Os.Builder osBuilder;
  private Distance.Builder distanceBuilder;
  private Uptime.Builder uptimeBuilder;
  private TcpSequence.Builder tcpSequenceBuilder;
  private IpIdSequence.Builder ipIdSequenceBuilder;
  private TcpTsSequence.Builder tcpTsSequenceBuilder;
  private HostScript.Builder hostScriptBuilder;
  private Trace.Builder traceBuilder;
  private Hop.Builder hopBuilder;
  private Times.Builder timesBuilder;
  private PortUsed.Builder portUsedBuilder;
  private OsMatch.Builder osMatchBuilder;
  private OsClass.Builder osClassBuilder;
  private OsFingerprint.Builder osFingerprintBuilder;
  private ExtraPorts.Builder extraPortsBuilder;
  private ExtraReasons.Builder extraReasonsBuilder;
  private Port.Builder portBuilder;
  private com.google.tsunami.plugins.portscan.nmap.client.result.State.Builder stateBuilder;
  private Owner.Builder ownerBuilder;
  private Service.Builder serviceBuilder;

  public NmapResultHandler() {
    this.stateStack = new ArrayDeque<>();
    this.tableBuilderStack = new ArrayDeque<>();
  }

  enum State {
    INIT,
    // nmaprun children.
    IN_NMAP_RUN,
    IN_SCAN_INFO,
    IN_VERBOSE,
    IN_DEBUGGING,
    IN_TARGET,
    IN_TASK_BEGIN,
    IN_TASK_PROGRESS,
    IN_TASK_END,
    IN_PRE_SCRIPT,
    IN_POST_SCRIPT,
    IN_HOST,
    IN_OUTPUT,
    IN_RUN_STATS,
    // runstats children.
    IN_FINISHED,
    IN_HOSTS,
    // common children.
    IN_SCRIPT,
    IN_CPE,
    // script children.
    IN_TABLE,
    IN_ELEM,
    // host children.
    IN_STATUS,
    IN_ADDRESS,
    IN_HOSTNAMES,
    IN_HOSTNAME,
    IN_SMURF,
    IN_PORTS,
    IN_OS,
    IN_DISTANCE,
    IN_UPTIME,
    IN_TCP_SEQUENCE,
    IN_IP_ID_SEQUENCE,
    IN_TCP_TS_SEQUENCE,
    IN_HOST_SCRIPT,
    IN_TRACE,
    IN_HOP,
    IN_TIMES,
    // os children.
    IN_PORT_USED,
    IN_OS_MATCH,
    IN_OS_CLASS,
    IN_OS_FINGERPRINT,
    // ports children.
    IN_EXTRA_PORTS,
    IN_EXTRA_REASONS,
    IN_PORT,
    // port children.
    IN_STATE,
    IN_OWNER,
    IN_SERVICE,
    UNRECOGNIZED_ELEMENT
  }

  public NmapRun getNmapRun() {
    return nmapRunBuilder.build();
  }

  @Override
  public void startDocument() {
    logger.atInfo().log("Start parsing Nmap result document.");
    pushState(State.INIT);
  }

  @Override
  public void endDocument() throws SAXException {
    logger.atInfo().log("Finished parsing Nmap result document.");
    exitState(State.INIT);
  }

  @Override
  public void startElement(String uri, String localName, String qName, Attributes attrs)
      throws SAXException {
    XmlAttributes attributes = XmlAttributes.from(attrs);
    switch (qName) {
      case NMAP_RUN_ELEM:
        enterState(State.INIT, State.IN_NMAP_RUN);
        nmapRunBuilder =
            NmapRun.builder()
                .setScanner(attributes.getValue("scanner", ""))
                .setArgs(attributes.getValue("args", ""))
                .setStart(attributes.getValue("start", ""))
                .setStartStr(attributes.getValue("startstr", ""))
                .setVersion(attributes.getValue("version", ""))
                .setProfileName(attributes.getValue("profile_name", ""))
                .setXmlOutputVersion(attributes.getValue("xmloutputversion", ""));
        break;
      // nmaprun children.
      case SCAN_INFO_ELEM:
        enterState(State.IN_NMAP_RUN, State.IN_SCAN_INFO);
        scanInfoBuilder =
            ScanInfo.builder()
                .setType(attributes.getValue("type", ""))
                .setScanFlags(attributes.getValue("scanflags", ""))
                .setProtocol(attributes.getValue("protocol", ""))
                .setNumServices(attributes.getValue("numservices", ""))
                .setServices(attributes.getValue("services", ""));
        break;
      case VERBOSE_ELEM:
        enterState(State.IN_NMAP_RUN, State.IN_VERBOSE);
        verboseBuilder = Verbose.builder().setLevel(attributes.getValue("level", ""));
        break;
      case DEBUGGING_ELEM:
        enterState(State.IN_NMAP_RUN, State.IN_DEBUGGING);
        debuggingBuilder = Debugging.builder().setLevel(attributes.getValue("level", ""));
        break;
      case TARGET_ELEM:
        enterState(State.IN_NMAP_RUN, State.IN_TARGET);
        targetBuilder =
            Target.builder()
                .setSpecification(attributes.getValue("specification", ""))
                .setStatus(attributes.getValue("status", ""))
                .setReason(attributes.getValue("reason", ""));
        break;
      case TASK_BEGIN_ELEM:
        enterState(State.IN_NMAP_RUN, State.IN_TASK_BEGIN);
        taskBeginBuilder =
            TaskBegin.builder()
                .setTask(attributes.getValue("task", ""))
                .setTime(attributes.getValue("time", ""))
                .setExtraInfo(attributes.getValue("extrainfo", ""));
        break;
      case TASK_PROGRESS_ELEM:
        enterState(State.IN_NMAP_RUN, State.IN_TASK_PROGRESS);
        taskProgressBuilder =
            TaskProgress.builder()
                .setTask(attributes.getValue("task", ""))
                .setTime(attributes.getValue("time", ""))
                .setPercent(attributes.getValue("percent", ""))
                .setRemaining(attributes.getValue("remaining", ""))
                .setEtc(attributes.getValue("etc", ""));
        break;
      case TASK_END_ELEM:
        enterState(State.IN_NMAP_RUN, State.IN_TASK_END);
        taskEndBuilder =
            TaskEnd.builder()
                .setTask(attributes.getValue("task", ""))
                .setTime(attributes.getValue("time", ""))
                .setExtraInfo(attributes.getValue("extrainfo", ""));
        break;
      case PRE_SCRIPT_ELEM:
        enterState(State.IN_NMAP_RUN, State.IN_PRE_SCRIPT);
        preScriptBuilder = PreScript.builder();
        break;
      case POST_SCRIPT_ELEM:
        enterState(State.IN_NMAP_RUN, State.IN_POST_SCRIPT);
        postScriptBuilder = PostScript.builder();
        break;
      case HOST_ELEM:
        enterState(State.IN_NMAP_RUN, State.IN_HOST);
        hostBuilder =
            Host.builder()
                .setStartTime(attributes.getValue("starttime", ""))
                .setEndTime(attributes.getValue("endtime", ""))
                .setComment(attributes.getValue("comment", ""));
        break;
      case OUTPUT_ELEM:
        enterTextCollectingState(State.IN_NMAP_RUN, State.IN_OUTPUT);
        outputBuilder = Output.builder().setType(attributes.getValue("type", ""));
        break;
      case RUN_STATS_ELEM:
        enterState(State.IN_NMAP_RUN, State.IN_RUN_STATS);
        runStatsBuilder = RunStats.builder();
        break;
      // runstats children.
      case FINISHED_ELEM:
        enterState(State.IN_RUN_STATS, State.IN_FINISHED);
        finishedBuilder =
            Finished.builder()
                .setTime(attributes.getValue("time", ""))
                .setTimeStr(attributes.getValue("timestr", ""))
                .setElapsed(attributes.getValue("elapsed", ""))
                .setSummary(attributes.getValue("summary", ""))
                .setExit(attributes.getValue("exit", ""))
                .setErrorMsg(attributes.getValue("errormsg", ""));
        break;
      case HOSTS_ELEM:
        enterState(State.IN_RUN_STATS, State.IN_HOSTS);
        hostsBuilder =
            Hosts.builder()
                .setUp(attributes.getValue("up", "0"))
                .setDown(attributes.getValue("down", "0"))
                .setTotal(attributes.getValue("total", ""));
        break;
      // common children.
      case SCRIPT_ELEM:
        if (!SCRIPT_ANCESTORS.contains(stateStack.peekFirst().state())) {
          throw newInvalidStateException(stateStack.peekFirst().state(), SCRIPT_ANCESTORS);
        }
        enterTextCollectingState(stateStack.peekFirst().state(), State.IN_SCRIPT);
        scriptBuilder =
            Script.builder()
                .setId(attributes.getValue("id", ""))
                .setOutput(attributes.getValue("output", ""));
        break;
      case CPE_ELEM:
        if (!CPE_ANCESTORS.contains(stateStack.peekFirst().state())) {
          throw newInvalidStateException(stateStack.peekFirst().state(), CPE_ANCESTORS);
        }
        enterTextCollectingState(stateStack.peekFirst().state(), State.IN_CPE);
        cpeBuilder = Cpe.builder();
        break;
      // script children.
      case TABLE_ELEM:
        if (!TABLE_ANCESTORS.contains(stateStack.peekFirst().state())) {
          throw newInvalidStateException(stateStack.peekFirst().state(), TABLE_ANCESTORS);
        }
        enterState(stateStack.peekFirst().state(), State.IN_TABLE);
        tableBuilderStack.addFirst(Table.builder().setKey(attributes.getValue("key", "")));
        break;
      case ELEM_ELEM:
        if (!ELEM_ANCESTORS.contains(stateStack.peekFirst().state())) {
          throw newInvalidStateException(stateStack.peekFirst().state(), ELEM_ANCESTORS);
        }
        enterTextCollectingState(stateStack.peekFirst().state(), State.IN_ELEM);
        elemBuilder = Elem.builder().setKey(attributes.getValue("key", ""));
        break;
      // host children.
      case STATUS_ELEM:
        enterState(State.IN_HOST, State.IN_STATUS);
        statusBuilder =
            Status.builder()
                .setState(attributes.getValue("state", ""))
                .setReason(attributes.getValue("reason", ""))
                .setReasonTtl(attributes.getValue("reason_ttl", ""));
        break;
      case ADDRESS_ELEM:
        enterState(State.IN_HOST, State.IN_ADDRESS);
        addressBuilder =
            Address.builder()
                .setAddr(attributes.getValue("addr", ""))
                .setAddrType(attributes.getValue("addrtype", "ipv4"))
                .setVendor(attributes.getValue("vendor", ""));
        break;
      case HOSTNAMES_ELEM:
        enterState(State.IN_HOST, State.IN_HOSTNAMES);
        hostnamesBuilder = Hostnames.builder();
        break;
      case HOSTNAME_ELEM:
        enterState(State.IN_HOSTNAMES, State.IN_HOSTNAME);
        hostnameBuilder =
            Hostname.builder()
                .setName(attributes.getValue("name", ""))
                .setType(attributes.getValue("type", ""));
        break;
      case SMURF_ELEM:
        enterState(State.IN_HOST, State.IN_SMURF);
        smurfBuilder = Smurf.builder().setResponses(attributes.getValue("responses", ""));
        break;
      case PORTS_ELEM:
        enterState(State.IN_HOST, State.IN_PORTS);
        portsBuilder = Ports.builder();
        break;
      case OS_ELEM:
        enterState(State.IN_HOST, State.IN_OS);
        osBuilder = Os.builder();
        break;
      case DISTANCE_ELEM:
        enterState(State.IN_HOST, State.IN_DISTANCE);
        distanceBuilder = Distance.builder().setValue(attributes.getValue("value", ""));
        break;
      case UPTIME_ELEM:
        enterState(State.IN_HOST, State.IN_UPTIME);
        uptimeBuilder =
            Uptime.builder()
                .setSeconds(attributes.getValue("seconds", ""))
                .setLastBoot(attributes.getValue("lastboot", ""));
        break;
      case TCP_SEQUENCE_ELEM:
        enterState(State.IN_HOST, State.IN_TCP_SEQUENCE);
        tcpSequenceBuilder =
            TcpSequence.builder()
                .setIndex(attributes.getValue("index", ""))
                .setDifficulty(attributes.getValue("difficulty", ""))
                .setValues(attributes.getValue("values", ""));
        break;
      case IP_ID_SEQUENCE_ELEM:
        enterState(State.IN_HOST, State.IN_IP_ID_SEQUENCE);
        ipIdSequenceBuilder =
            IpIdSequence.builder()
                .setClazz(attributes.getValue("class", ""))
                .setValues(attributes.getValue("values", ""));
        break;
      case TCP_TS_SEQUENCE_ELEM:
        enterState(State.IN_HOST, State.IN_TCP_TS_SEQUENCE);
        tcpTsSequenceBuilder =
            TcpTsSequence.builder()
                .setClazz(attributes.getValue("class", ""))
                .setValues(attributes.getValue("values", ""));
        break;
      case HOST_SCRIPT_ELEM:
        enterState(State.IN_HOST, State.IN_HOST_SCRIPT);
        hostScriptBuilder = HostScript.builder();
        break;
      case TRACE_ELEM:
        enterState(State.IN_HOST, State.IN_TRACE);
        traceBuilder =
            Trace.builder()
                .setProto(attributes.getValue("proto", ""))
                .setPort(attributes.getValue("port", ""));
        break;
      case HOP_ELEM:
        enterState(State.IN_TRACE, State.IN_HOP);
        hopBuilder =
            Hop.builder()
                .setTtl(attributes.getValue("ttl", ""))
                .setRtt(attributes.getValue("rtt", ""))
                .setIpAddr(attributes.getValue("ipaddr", ""))
                .setHost(attributes.getValue("host", ""));
        break;
      case TIMES_ELEM:
        enterState(State.IN_HOST, State.IN_TIMES);
        timesBuilder =
            Times.builder()
                .setSrtt(attributes.getValue("srtt", ""))
                .setRttVar(attributes.getValue("rttvar", ""))
                .setTo(attributes.getValue("to", ""));
        break;
      // os children.
      case PORT_USED_ELEM:
        enterState(State.IN_OS, State.IN_PORT_USED);
        portUsedBuilder =
            PortUsed.builder()
                .setState(attributes.getValue("state", ""))
                .setProto(attributes.getValue("proto", ""))
                .setPortId(attributes.getValue("portid", ""));
        break;
      case OS_MATCH_ELEM:
        enterState(State.IN_OS, State.IN_OS_MATCH);
        osMatchBuilder =
            OsMatch.builder()
                .setName(attributes.getValue("name", ""))
                .setAccuracy(attributes.getValue("accuracy", ""))
                .setLine(attributes.getValue("line", ""));
        break;
      case OS_CLASS_ELEM:
        enterState(State.IN_OS_MATCH, State.IN_OS_CLASS);
        osClassBuilder =
            OsClass.builder()
                .setVendor(attributes.getValue("vendor", ""))
                .setOsGen(attributes.getValue("osgen", ""))
                .setType(attributes.getValue("type", ""))
                .setAccuracy(attributes.getValue("accuracy", ""))
                .setOsFamily(attributes.getValue("osfamily", ""));
        break;
      case OS_FINGERPRINT_ELEM:
        enterState(State.IN_OS, State.IN_OS_FINGERPRINT);
        osFingerprintBuilder =
            OsFingerprint.builder().setFingerprint(attributes.getValue("fingerprint", ""));
        break;
      // ports children.
      case EXTRA_PORTS_ELEM:
        enterState(State.IN_PORTS, State.IN_EXTRA_PORTS);
        extraPortsBuilder =
            ExtraPorts.builder()
                .setState(attributes.getValue("state", ""))
                .setCount(attributes.getValue("count", ""));
        break;
      case EXTRA_REASONS_ELEM:
        enterState(State.IN_EXTRA_PORTS, State.IN_EXTRA_REASONS);
        extraReasonsBuilder =
            ExtraReasons.builder()
                .setReason(attributes.getValue("reason", ""))
                .setCount(attributes.getValue("count", ""));
        break;
      case PORT_ELEM:
        enterState(State.IN_PORTS, State.IN_PORT);
        portBuilder =
            Port.builder()
                .setProtocol(attributes.getValue("protocol", ""))
                .setPortId(attributes.getValue("portid", ""));
        break;
      // port children.
      case STATE_ELEM:
        enterState(State.IN_PORT, State.IN_STATE);
        stateBuilder =
            com.google.tsunami.plugins.portscan.nmap.client.result.State.builder()
                .setState(attributes.getValue("state", ""))
                .setReason(attributes.getValue("reason", ""))
                .setReasonTtl(attributes.getValue("reason_ttl", ""))
                .setReasonIp(attributes.getValue("reason_ip", ""));
        break;
      case OWNER_ELEM:
        enterState(State.IN_PORT, State.IN_OWNER);
        ownerBuilder = Owner.builder().setName(attributes.getValue("name", ""));
        break;
      case SERVICE_ELEM:
        enterState(State.IN_PORT, State.IN_SERVICE);
        serviceBuilder =
            Service.builder()
                .setName(attributes.getValue("name", ""))
                .setConf(attributes.getValue("conf", ""))
                .setMethod(attributes.getValue("method", ""))
                .setVersion(attributes.getValue("version", ""))
                .setProduct(attributes.getValue("product", ""))
                .setExtraInfo(attributes.getValue("extrainfo", ""))
                .setTunnel(attributes.getValue("tunnel", ""))
                .setProto(attributes.getValue("proto", ""))
                .setRpcNum(attributes.getValue("rpcnum", ""))
                .setLowVer(attributes.getValue("lowver", ""))
                .setHighVer(attributes.getValue("highver", ""))
                .setHostname(attributes.getValue("hostname", ""))
                .setOsType(attributes.getValue("ostype", ""))
                .setDeviceType(attributes.getValue("devicetype", ""))
                .setServiceFp(attributes.getValue("servicefp", ""));
        break;
      default:
        pushState(State.UNRECOGNIZED_ELEMENT);
    }
  }

  @Override
  public void endElement(String uri, String localName, String qName) throws SAXException {
    switch (qName) {
      case NMAP_RUN_ELEM:
        exitState(State.IN_NMAP_RUN);
        break;
      // nmaprun children.
      case SCAN_INFO_ELEM:
        exitState(State.IN_SCAN_INFO);
        nmapRunBuilder.addScanInfo(scanInfoBuilder.build());
        break;
      case VERBOSE_ELEM:
        exitState(State.IN_VERBOSE);
        nmapRunBuilder.setVerbose(verboseBuilder.build());
        break;
      case DEBUGGING_ELEM:
        exitState(State.IN_DEBUGGING);
        nmapRunBuilder.setDebugging(debuggingBuilder.build());
        break;
      case TARGET_ELEM:
        exitState(State.IN_TARGET);
        nmapRunBuilder.addValueElement(targetBuilder.build());
        break;
      case TASK_BEGIN_ELEM:
        exitState(State.IN_TASK_BEGIN);
        nmapRunBuilder.addValueElement(taskBeginBuilder.build());
        break;
      case TASK_PROGRESS_ELEM:
        exitState(State.IN_TASK_PROGRESS);
        nmapRunBuilder.addValueElement(taskProgressBuilder.build());
        break;
      case TASK_END_ELEM:
        exitState(State.IN_TASK_END);
        nmapRunBuilder.addValueElement(taskEndBuilder.build());
        break;
      case PRE_SCRIPT_ELEM:
        exitState(State.IN_PRE_SCRIPT);
        nmapRunBuilder.addValueElement(preScriptBuilder.build());
        break;
      case POST_SCRIPT_ELEM:
        exitState(State.IN_POST_SCRIPT);
        nmapRunBuilder.addValueElement(postScriptBuilder.build());
        break;
      case HOST_ELEM:
        exitState(State.IN_HOST);
        nmapRunBuilder.addValueElement(hostBuilder.build());
        break;
      case OUTPUT_ELEM:
        SaxHandlerState outputState = exitState(State.IN_OUTPUT);
        nmapRunBuilder.addValueElement(
            outputBuilder.setValue(outputState.textValueBuilder().toString()).build());
        break;
      case RUN_STATS_ELEM:
        exitState(State.IN_RUN_STATS);
        nmapRunBuilder.setRunStats(runStatsBuilder.build());
        break;
      // runstats finished.
      case FINISHED_ELEM:
        exitState(State.IN_FINISHED);
        runStatsBuilder.setFinished(finishedBuilder.build());
        break;
      case HOSTS_ELEM:
        exitState(State.IN_HOSTS);
        runStatsBuilder.setHosts(hostsBuilder.build());
        break;
      // common children.
      case SCRIPT_ELEM:
        {
          SaxHandlerState scriptState = exitState(State.IN_SCRIPT);
          State prevState = stateStack.peekFirst().state();
          Script script =
              scriptBuilder.addValueElement(scriptState.textValueBuilder().toString()).build();
          if (prevState.equals(State.IN_PRE_SCRIPT)) {
            preScriptBuilder.addScript(script);
          } else if (prevState.equals(State.IN_POST_SCRIPT)) {
            postScriptBuilder.addScript(script);
          } else if (prevState.equals(State.IN_HOST_SCRIPT)) {
            hostScriptBuilder.addScript(script);
          } else if (prevState.equals(State.IN_PORT)) {
            portBuilder.addScript(script);
          } else {
            throw newInvalidStateException(prevState, SCRIPT_ANCESTORS);
          }
          break;
        }
      case CPE_ELEM:
        {
          SaxHandlerState cpeState = exitState(State.IN_CPE);
          State prevState = stateStack.peekFirst().state();
          Cpe cpe = cpeBuilder.setValue(cpeState.textValueBuilder().toString()).build();
          if (prevState.equals(State.IN_OS_CLASS)) {
            osClassBuilder.addCpe(cpe);
          } else if (prevState.equals(State.IN_SERVICE)) {
            serviceBuilder.addCpe(cpe);
          } else {
            throw newInvalidStateException(prevState, CPE_ANCESTORS);
          }
          break;
        }
      // script children.
      case TABLE_ELEM:
        {
          exitState(State.IN_TABLE);
          State prevState = stateStack.peekFirst().state();
          Table table = tableBuilderStack.removeFirst().build();
          if (prevState.equals(State.IN_SCRIPT)) {
            scriptBuilder.addValueElement(table);
          } else if (prevState.equals(State.IN_TABLE)) {
            tableBuilderStack.peekFirst().addValueElement(table);
          } else {
            throw newInvalidStateException(prevState, TABLE_ANCESTORS);
          }
          break;
        }
      case ELEM_ELEM:
        {
          SaxHandlerState elemState = exitState(State.IN_ELEM);
          State prevState = stateStack.peekFirst().state();
          Elem elem = elemBuilder.setValue(elemState.textValueBuilder().toString()).build();
          if (prevState.equals(State.IN_SCRIPT)) {
            scriptBuilder.addValueElement(elem);
          } else if (prevState.equals(State.IN_TABLE)) {
            tableBuilderStack.peekFirst().addValueElement(elem);
          } else {
            throw newInvalidStateException(prevState, ELEM_ANCESTORS);
          }
          break;
        }
      // host children.
      case STATUS_ELEM:
        exitState(State.IN_STATUS);
        hostBuilder.addValueElement(statusBuilder.build());
        break;
      case ADDRESS_ELEM:
        exitState(State.IN_ADDRESS);
        hostBuilder.addValueElement(addressBuilder.build());
        break;
      case HOSTNAMES_ELEM:
        exitState(State.IN_HOSTNAMES);
        hostBuilder.addValueElement(hostnamesBuilder.build());
        break;
      case HOSTNAME_ELEM:
        exitState(State.IN_HOSTNAME);
        hostnamesBuilder.addHostname(hostnameBuilder.build());
        break;
      case SMURF_ELEM:
        exitState(State.IN_SMURF);
        hostBuilder.addValueElement(smurfBuilder.build());
        break;
      case PORTS_ELEM:
        exitState(State.IN_PORTS);
        hostBuilder.addValueElement(portsBuilder.build());
        break;
      case OS_ELEM:
        exitState(State.IN_OS);
        hostBuilder.addValueElement(osBuilder.build());
        break;
      case DISTANCE_ELEM:
        exitState(State.IN_DISTANCE);
        hostBuilder.addValueElement(distanceBuilder.build());
        break;
      case UPTIME_ELEM:
        exitState(State.IN_UPTIME);
        hostBuilder.addValueElement(uptimeBuilder.build());
        break;
      case TCP_SEQUENCE_ELEM:
        exitState(State.IN_TCP_SEQUENCE);
        hostBuilder.addValueElement(tcpSequenceBuilder.build());
        break;
      case IP_ID_SEQUENCE_ELEM:
        exitState(State.IN_IP_ID_SEQUENCE);
        hostBuilder.addValueElement(ipIdSequenceBuilder.build());
        break;
      case TCP_TS_SEQUENCE_ELEM:
        exitState(State.IN_TCP_TS_SEQUENCE);
        hostBuilder.addValueElement(tcpTsSequenceBuilder.build());
        break;
      case HOST_SCRIPT_ELEM:
        exitState(State.IN_HOST_SCRIPT);
        hostBuilder.addValueElement(hostScriptBuilder.build());
        break;
      case TRACE_ELEM:
        exitState(State.IN_TRACE);
        hostBuilder.addValueElement(traceBuilder.build());
        break;
      case HOP_ELEM:
        exitState(State.IN_HOP);
        traceBuilder.addHop(hopBuilder.build());
        break;
      case TIMES_ELEM:
        exitState(State.IN_TIMES);
        hostBuilder.addValueElement(timesBuilder.build());
        break;
      // os children.
      case PORT_USED_ELEM:
        exitState(State.IN_PORT_USED);
        osBuilder.addPortUsed(portUsedBuilder.build());
        break;
      case OS_MATCH_ELEM:
        exitState(State.IN_OS_MATCH);
        osBuilder.addOsMatch(osMatchBuilder.build());
        break;
      case OS_CLASS_ELEM:
        exitState(State.IN_OS_CLASS);
        osMatchBuilder.addOsClass(osClassBuilder.build());
        break;
      case OS_FINGERPRINT_ELEM:
        exitState(State.IN_OS_FINGERPRINT);
        osBuilder.addOsFingerprint(osFingerprintBuilder.build());
        break;
      // ports children.
      case EXTRA_PORTS_ELEM:
        exitState(State.IN_EXTRA_PORTS);
        portsBuilder.addExtraPorts(extraPortsBuilder.build());
        break;
      case EXTRA_REASONS_ELEM:
        exitState(State.IN_EXTRA_REASONS);
        extraPortsBuilder.addExtraReasons(extraReasonsBuilder.build());
        break;
      case PORT_ELEM:
        exitState(State.IN_PORT);
        portsBuilder.addPort(portBuilder.build());
        break;
      // port children.
      case STATE_ELEM:
        exitState(State.IN_STATE);
        portBuilder.setState(stateBuilder.build());
        break;
      case OWNER_ELEM:
        exitState(State.IN_OWNER);
        portBuilder.setOwner(ownerBuilder.build());
        break;
      case SERVICE_ELEM:
        exitState(State.IN_SERVICE);
        portBuilder.setService(serviceBuilder.build());
        break;
      default:
        exitState(State.UNRECOGNIZED_ELEMENT);
    }
  }

  @Override
  public void characters(char[] ch, int start, int length) {
    if (stateStack.peekFirst().textValueBuilder() != null) {
      stateStack.peek().textValueBuilder().append(ch, start, length);
    }
  }

  private void pushState(State newState) {
    checkNotNull(newState);
    stateStack.addFirst(SaxHandlerState.create(newState, null));
  }

  private void enterState(State expectedCurrentState, State newState) throws SAXException {
    enterStateImpl(expectedCurrentState, newState, false);
  }

  private void enterTextCollectingState(State expectedCurrentState, State newState)
      throws SAXException {
    enterStateImpl(expectedCurrentState, newState, true);
  }

  private void enterStateImpl(State expectedCurrentState, State newState, boolean collectText)
      throws SAXException {
    SaxHandlerState curParserState = stateStack.peekFirst();
    if (!curParserState.state().equals(expectedCurrentState)) {
      throw newInvalidStateException(curParserState.state(), expectedCurrentState);
    }
    stateStack.addFirst(SaxHandlerState.create(newState, collectText ? new StringBuilder() : null));
  }

  private SaxHandlerState exitState(State expectedCurrentState) throws SAXException {
    SaxHandlerState curParserState = stateStack.peekFirst();
    if (!curParserState.state().equals(expectedCurrentState)) {
      throw newInvalidStateException(curParserState.state(), expectedCurrentState);
    }
    return stateStack.removeFirst();
  }

  private static SAXException newInvalidStateException(
      State currentState, State expectedState, State... otherExpectedStates) {
    return newInvalidStateException(
        currentState,
        ImmutableList.<State>builder()
            .add(expectedState)
            .addAll(Arrays.asList(otherExpectedStates))
            .build());
  }

  private static SAXException newInvalidStateException(
      State currentState, Iterable<State> expectedStates) {
    return new SAXException(
        String.format(
            "Invalid parser state: (expected:'one of [%s]', actual:'%s')",
            Joiner.on(",").join(expectedStates), currentState));
  }

  @AutoValue
  abstract static class SaxHandlerState {
    abstract State state();
    @Nullable abstract StringBuilder textValueBuilder();

    static SaxHandlerState create(State state, @Nullable StringBuilder textValueBuilder) {
      return new AutoValue_NmapResultHandler_SaxHandlerState(state, textValueBuilder);
    }
  }
}
