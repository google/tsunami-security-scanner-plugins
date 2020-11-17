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

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;
import static java.util.stream.Collectors.joining;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableList;
import com.google.tsunami.common.command.CommandExecutor;
import com.google.tsunami.common.command.CommandExecutorFactory;
import com.google.tsunami.common.data.NetworkEndpointUtils;
import com.google.tsunami.plugins.portscan.nmap.client.data.IPortTarget;
import com.google.tsunami.plugins.portscan.nmap.client.data.PortRange;
import com.google.tsunami.plugins.portscan.nmap.client.data.ScriptAndArgs;
import com.google.tsunami.plugins.portscan.nmap.client.data.SinglePort;
import com.google.tsunami.plugins.portscan.nmap.client.parser.XMLParser;
import com.google.tsunami.plugins.portscan.nmap.client.result.NmapRun;
import com.google.tsunami.proto.NetworkEndpoint;
import com.google.tsunami.proto.TransportProtocol;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executor;
import java.util.stream.Stream;
import javax.inject.Inject;
import javax.xml.parsers.ParserConfigurationException;
import org.xml.sax.SAXException;

/**
 * Client for the open-source nmap tool. Nmap is a network security scanner with support for
 * advanced OS fingerprint, service discovery and service fingerprinting techniques. For more
 * details, check <a href="https://nmap.org/">link</>.
 *
 * <p>Example scanning host 1.1.1.1 with SYN host discovery and port scanning on port 0-1024, 8080
 * and 9919:
 *
 * <pre>
 *   NmapRun scanRunResult =
 *         new NmapClient(nmapFile.getAbsolutePath())
 *             .withTargetNetworkEndpoint(NetworkEndpoints.forIp("1.1.1.1"))
 *             .withHostDiscoveryTechnique(HostDiscoveryTechnique.SYN)
 *             .withScanTechnique(ScanTechnique.SYN)
 *             .onPortRange(0, 1024)
 *             .onPort(8080)
 *             .onPort(9919)
 *             .run();
 * </pre>
 */
public class NmapClient {

  /**
   * Techniques to determine if the host is alive before performing and exhaustive scan. ee <a
   * href="https://nmap.org/book/man-host-discovery.html">link</> for full details on each
   * technique.
   */
  public enum HostDiscoveryTechnique {
    SYN("-PS"),
    ACK("-PA"),
    UDP("-PU"),
    SCTP("-PY"),
    ICMP_ECHO("-PE"),
    ICMP_TIMESTAMP("-PT"),
    ICMP_NETMASK("-PM"),
    IP_PROTOCOL("-P0");

    private final String flag;

    HostDiscoveryTechnique(String flag) {
      this.flag = flag;
    }

    String getFlag() {
      return flag;
    }
  }

  /**
   * Technique to list open/closed/filtered ports, see <a
   * href="https://nmap.org/book/man-port-scanning-techniques.html">link</> for full details on each
   * technique.
   */
  public enum ScanTechnique {
    SYN("-sS"),
    CONNECT("-sT"),
    ACK("-sA"),
    WINDOW("-sW"),
    MAIMON("-sM"),
    UDP("-sU"),
    SCTP_INIT("-sY"),
    SCTP_COOKIE("-sZ"),
    TCP_NULL("-sN"),
    TCP_FIN("-sF"),
    TCP_XMAS("-sX"),
    IP_PROTOCOL("-s0");

    private final String flag;

    ScanTechnique(String flag) {
      this.flag = flag;
    }

    String getFlag() {
      return flag;
    }
  }

  /** Modes to resolve DNS names. */
  public enum DnsResolution {
    DEFAULT(Optional.empty()),
    ALWAYS(Optional.of("-R")),
    NEVER(Optional.of("-n"));

    private final Optional<String> flag;

    DnsResolution(Optional<String> flag) {
      this.flag = flag;
    }

    Optional<String> getFlag() {
      return flag;
    }
  }

  /**
   * Timing templates controlling min, max and initial RTT timeout, max retries, scan delay, TCP and
   * UDP scan delay, host timeout and max parallelism. For the exact values set for each
   * configurable parameter, check <a
   * href="https://nmap.org/book/performance-timing-templates.html">link</a>.
   */
  public enum TimingTemplate {
    PARANOID(0),
    SNEAKY(1),
    POLITE(2),
    NORMAL(3),
    AGGRESSIVE(4),
    INSANE(5);

    private final int value;

    TimingTemplate(int value) {
      this.value = value;
    }

    String getFlag() {
      return String.format("-T%d", this.value);
    }
  }

  /**
   * Privileged modes to use to run nmap. Default mode will check {@code geteuid} is equal to 0 if
   * the scan requires raw socket manipulation or sniffing. Privileged is useful if the proper
   * capabilities are assigned and {@code geteuid} is not equal to 0. Unprivileged is helpful for
   * debugging.
   */
  private enum PrivilegedMode {
    DEFAULT(Optional.empty()),
    PRIVILEGED(Optional.of("--privileged")),
    UNPRIVILEGED(Optional.of("--unprivileged"));

    private final Optional<String> flag;

    PrivilegedMode(Optional<String> flag) {
      this.flag = flag;
    }

    Optional<String> getFlag() {
      return flag;
    }
  }

  private final String nmapBinaryPath;
  private final List<NetworkEndpoint> networkEndpoints = new ArrayList<>();
  private final List<HostDiscoveryTechnique> hostDiscoveryTechniques = new ArrayList<>();
  private final List<String> dnsServers = new ArrayList<>();
  private final List<ScanTechnique> scanTechniques = new ArrayList<>();
  private final List<IPortTarget> targetPorts = new ArrayList<>();
  private final List<ScriptAndArgs> scriptAndArgs = new ArrayList<>();
  private final File report;
  private boolean treatAllHostsAsOnline = false;
  private boolean traceroute = false;
  private boolean fastScan = false;
  private boolean serviceAndVersionDetection = false;
  private boolean osDetection = false;
  private PrivilegedMode privilegedMode = PrivilegedMode.DEFAULT;
  private DnsResolution dnsResolution = DnsResolution.DEFAULT;
  private Optional<Integer> versionDetectionIntensity = Optional.empty();
  private Optional<TimingTemplate> timing = Optional.empty();

  /** Constructor using runtime nmap path. */
  @Inject
  public NmapClient(@NmapBinaryPath String nmapBinaryPath) throws IOException {
    this(nmapBinaryPath, File.createTempFile("nmap", ".report"));
  }

  /**
   * Client constructor.
   *
   * @param nmapBinaryPath Path to the nmap binary.
   */
  public NmapClient(String nmapBinaryPath, File report) {
    checkArgument(
        Files.exists(Paths.get(nmapBinaryPath)), "Binary %s do not exist", nmapBinaryPath);
    this.nmapBinaryPath = nmapBinaryPath;
    this.report = report;
  }

  /**
   * Start scan by executing the nmap binary, waits for the process to finish and then parses and
   * returns the results.
   *
   * @param executor Executor to collect process output and error streams. Important to use an
   *     executor suitable for long running and IO blocking tasks. {@link
   *     java.util.concurrent.ThreadPoolExecutor} is a viable option.
   */
  public NmapRun run(Executor executor)
      throws IOException, InterruptedException, ExecutionException, ParserConfigurationException,
          SAXException {
    ArrayList<String> arrayList = buildRunCommandArgs();
    String[] args = arrayList.toArray(new String[0]);
    CommandExecutor commandExecutor = CommandExecutorFactory.create(args);
    Process currentProcess = commandExecutor.execute(executor);
    currentProcess.waitFor();
    return XMLParser.parse(new FileInputStream(report));
  }

  @VisibleForTesting
  ArrayList<String> buildRunCommandArgs() {
    ArrayList<String> runCommandArgs = new ArrayList<>();

    runCommandArgs.add(nmapBinaryPath);

    privilegedMode.getFlag().ifPresent(runCommandArgs::add);

    if (treatAllHostsAsOnline) {
      runCommandArgs.add("-Pn");
    }

    hostDiscoveryTechniques.forEach(technique -> runCommandArgs.add(technique.getFlag()));

    dnsResolution.getFlag().ifPresent(runCommandArgs::add);

    if (!dnsServers.isEmpty()) {
      runCommandArgs.add("--dns-servers");
      runCommandArgs.add(dnsServers.stream().collect(joining(",")));
    }

    if (traceroute) {
      runCommandArgs.add("--traceroute");
    }

    scanTechniques.forEach(technique -> runCommandArgs.add(technique.getFlag()));

    if (!targetPorts.isEmpty()) {
      runCommandArgs.add("-p");
      runCommandArgs.add(
          Stream.concat(
                  // According to https://nmap.org/book/man-port-specification.html, once a protocol
                  // is specified, nmap will use the same protocol for all subsequent ports, so we
                  // add the ports with no specific protocols first.
                  targetPorts.stream()
                      .filter(port -> !port.isProtocolSpecified())
                      .map(IPortTarget::getCommandLineRepresentation),
                  targetPorts.stream()
                      .filter(IPortTarget::isProtocolSpecified)
                      .map(IPortTarget::getCommandLineRepresentation))
              .collect(joining(",")));
    }

    if (fastScan) {
      runCommandArgs.add("-F");
    }

    if (serviceAndVersionDetection) {
      runCommandArgs.add("-sV");
    }

    versionDetectionIntensity.ifPresent(
        integer -> {
          runCommandArgs.add("--version-intensity");
          runCommandArgs.add(Integer.toString(integer));
        });

    if (osDetection) {
      runCommandArgs.add("-O");
    }

    timing.ifPresent(value -> runCommandArgs.add(value.getFlag()));

    for (ScriptAndArgs script : scriptAndArgs) {
      runCommandArgs.add("--script");
      runCommandArgs.add(script.scriptName());
      if (!script.args().isEmpty()) {
        runCommandArgs.add("--script-args");
        runCommandArgs.add(script.args().stream().collect(joining(",")));
      }
    }

    if (networkEndpoints.stream().anyMatch(NetworkEndpointUtils::isIpV6Endpoint)) {
      runCommandArgs.add("-6");
    }

    networkEndpoints.stream()
        .map(NmapClient::networkEndpointToCliRepresentation)
        .forEach(runCommandArgs::add);

    runCommandArgs.add("-oX");
    runCommandArgs.add(report.getAbsolutePath());

    return runCommandArgs;
  }

  private static String networkEndpointToCliRepresentation(NetworkEndpoint networkEndpoint) {
    switch (networkEndpoint.getType()) {
      case IP:
      case IP_HOSTNAME:
        return networkEndpoint.getIpAddress().getAddress();
      case HOSTNAME:
        return networkEndpoint.getHostname().getName();
      default:
        throw new AssertionError("Invalid NetworkEndpoint type for Nmap.");
    }
  }

  /**
   * Sets the network endpoint to scan, multiple network endpoints can be set by calling the method
   * multiple times.
   *
   * @param networkEndpoint The network endpoint to scan.
   */
  public NmapClient withTargetNetworkEndpoint(NetworkEndpoint networkEndpoint) {
    this.networkEndpoints.add(networkEndpoint);
    return this;
  }

  /**
   * Skips the host discovery stage, this causes nmap to perform scanning even if the host is dead.
   * This method is incompatible with {@link
   * NmapClient#withHostDiscoveryTechnique(HostDiscoveryTechnique)}.
   */
  public NmapClient treatAllHostsAsOnline() {
    treatAllHostsAsOnline = true;
    return this;
  }

  /**
   * Sets the host discovery techniques to use. Several techniques can be set by calling the method
   * multiple time. This method is incompatible with {@link NmapClient#treatAllHostsAsOnline()}.
   *
   * @param technique The host discovery technique to use (SYN, ACK ...), check {@link
   *     NmapClient.HostDiscoveryTechnique} for a full list of supported techniques. For more
   *     details on each technique, check the following <a
   *     href="https://nmap.org/book/man-host-discovery.html">link</>.
   */
  public NmapClient withHostDiscoveryTechnique(HostDiscoveryTechnique technique) {
    checkNotNull(technique);
    hostDiscoveryTechniques.add(technique);
    return this;
  }

  /**
   * Set the DNS resolution mode (Default, Always or Never).
   *
   * @param resolution Resolution mode to use.
   */
  public NmapClient withDnsResolution(DnsResolution resolution) {
    dnsResolution = resolution;
    return this;
  }

  /**
   * Sets the DNS servers to use for DNS resolution. The value will be ignored if the resolution
   * mode is set to never or an IP v6 target is scanned. This behavior is enforced by nmap and
   * not by the {@link NmapClient}. See <a
   * href="https://nmap.org/book/host-discovery-dns.html>link</a> for extra details.
   *
   * @param servers DNS server to perform Domain resolution.
   */
  public NmapClient resolveWithDnsServer(String... servers) {
    Collections.addAll(dnsServers, servers);
    return this;
  }

  /** Requests tracing path to host using ICMP TTL decrement. */
  public NmapClient withTraceroute() {
    traceroute = true;
    return this;
  }

  /**
   * Set the port scanning technique to use. Multiple techniques can be set by calling the method
   * multiple times. For details on supported scanning techniques, check <a
   * href="https://nmap.org/book/man-port-scanning-techniques.html">link</a>.
   *
   * @param technique The port scanning technique.
   */
  public NmapClient withScanTechnique(ScanTechnique technique) {
    checkNotNull(technique);
    scanTechniques.add(technique);
    return this;
  }

  /**
   * Sets a single range to be scanned. The port range is protocol agnostic and will depend on the
   * scan technique set with {@link NmapClient#withScanTechnique(ScanTechnique)} method.
   *
   * @param port Port number.
   */
  public NmapClient onPort(int port, TransportProtocol protocol) {
    this.targetPorts.add(SinglePort.create(port, protocol));
    return this;
  }

  /**
   * Sets a port range to be scanned. The port range is protocol agnostic and will depend on the
   * scan technique set with {@link NmapClient#withScanTechnique(ScanTechnique)} method.
   *
   * @param startPort Start port.
   * @param endPort End port.
   */
  public NmapClient onPortRange(int startPort, int endPort, TransportProtocol protocol) {
    this.targetPorts.add(PortRange.create(startPort, endPort, protocol));
    return this;
  }

  /** Enables fast scan mode which only covers the top 100 most common ports in each protocol. */
  public NmapClient withFastScanMode() {
    fastScan = true;
    return this;
  }

  /**
   * Enables service and version detection. Version detection uses an internal database of probes to
   * determine the running service and extract version. For extra details on nmap version detection
   * capabilities, check <a href="https://nmap.org/book/vscan.html">link</a>.
   */
  public NmapClient withServiceAndVersionDetection() {
    serviceAndVersionDetection = true;
    return this;
  }

  /**
   * Sets version detection intensity. This requires the {@link
   * NmapClient#withServiceAndVersionDetection()} method to be set.
   *
   * @param intensity Intensity level to use (0 to 9 inclusive).
   */
  public NmapClient withVersionDetectionIntensity(int intensity) {
    checkArgument(intensity <= 9, "Intensity is less than 9");
    checkArgument(intensity >= 0, "Intensity is superior to 0");
    versionDetectionIntensity = Optional.of(intensity);
    return this;
  }

  /**
   * Adds an NSE scripts and corresponding flags. <a href="https://nmap.org/book/nse.html">Nmap
   * Scripting Engine (NSE)</a> are LUA scripts to automate a variety of tasks, from network
   * discovery to vulnerability discovery and version detection. Nmap ships with a rich <a
   * href="https://nmap.org/nsedoc/">set of NSE scripts<a/>. Multiple scripts can be set by calling
   * the {@link NmapClient#withScript(String, String...)} multiple times.
   *
   * <p>WARNING: scripts are not vetted and can be vulnerable to injection. Make sure the input used
   * here is controlled or review the nse script for vulnerabilities.
   *
   * @param scriptName The name script.
   * @param args Arguments of the script if any.
   */
  public NmapClient withScript(String scriptName, String... args) {
    scriptAndArgs.add(ScriptAndArgs.create(scriptName, ImmutableList.copyOf(args)));
    return this;
  }

  /** Enables OS fingerprinting using the TCP/IP probes heuristics. */
  public NmapClient withOsDetection() {
    osDetection = true;
    return this;
  }

  /**
   * Sets the timing template to use. Timing templates controls min, max and initial RTT timeout,
   * max retries, scan delay, TCP and UDP scan delay, host timeout and max parallelism. For the
   * exact values set for each configurable parameter, check <a
   * href="https://nmap.org/book/performance-timing-templates.html">link</a>.
   */
  public NmapClient withTimingTemplate(TimingTemplate template) {
    this.timing = Optional.of(template);
    return this;
  }

  /**
   * Forces nmap to assume the user is already privileged, this is required if the user is not
   * privileged, but the following capabilities are granted: {@code cap_net_raw} {@code
   * cap_net_admin} {@code cap_net_service+eip}
   *
   * <p>This is only needed for raw socket manipulation and sniffing. This method is incompatible
   * with {@link NmapClient#asUnprivileged()}.
   */
  public NmapClient asPrivileged() {
    privilegedMode = PrivilegedMode.PRIVILEGED;
    return this;
  }

  /**
   * Forces nmap to assume the user is unprivileged. Useful for testing and debugging. method is
   * incompatible with {@link NmapClient#asPrivileged()} and only the last call will be taken into
   * account.
   */
  public NmapClient asUnprivileged() {
    privilegedMode = PrivilegedMode.UNPRIVILEGED;
    return this;
  }
}
