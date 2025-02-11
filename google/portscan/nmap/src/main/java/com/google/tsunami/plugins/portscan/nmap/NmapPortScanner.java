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
package com.google.tsunami.plugins.portscan.nmap;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;

import com.google.common.base.Ascii;
import com.google.common.base.Splitter;
import com.google.common.base.Stopwatch;
import com.google.common.base.Strings;
import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.tsunami.common.command.CommandExecutionThreadPool;
import com.google.tsunami.common.data.NetworkEndpointUtils;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClientCliOptions;
import com.google.tsunami.plugin.PluginType;
import com.google.tsunami.plugin.PortScanner;
import com.google.tsunami.plugin.annotations.PluginInfo;
import com.google.tsunami.plugins.portscan.nmap.client.NmapClient;
import com.google.tsunami.plugins.portscan.nmap.client.NmapClient.DnsResolution;
import com.google.tsunami.plugins.portscan.nmap.client.NmapClient.ScanTechnique;
import com.google.tsunami.plugins.portscan.nmap.client.NmapClient.TimingTemplate;
import com.google.tsunami.plugins.portscan.nmap.client.result.Address;
import com.google.tsunami.plugins.portscan.nmap.client.result.Cpe;
import com.google.tsunami.plugins.portscan.nmap.client.result.Host;
import com.google.tsunami.plugins.portscan.nmap.client.result.Hostname;
import com.google.tsunami.plugins.portscan.nmap.client.result.NmapRun;
import com.google.tsunami.plugins.portscan.nmap.client.result.OsClass;
import com.google.tsunami.plugins.portscan.nmap.client.result.Port;
import com.google.tsunami.plugins.portscan.nmap.client.result.Ports;
import com.google.tsunami.plugins.portscan.nmap.client.result.Script;
import com.google.tsunami.plugins.portscan.nmap.option.NmapPortScannerCliOptions;
import com.google.tsunami.proto.NetworkEndpoint;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.OperatingSystemClass;
import com.google.tsunami.proto.PortScanningReport;
import com.google.tsunami.proto.ScanTarget;
import com.google.tsunami.proto.ServiceContext;
import com.google.tsunami.proto.Software;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.TransportProtocol;
import com.google.tsunami.proto.Version;
import com.google.tsunami.proto.Version.VersionType;
import com.google.tsunami.proto.VersionSet;
import com.google.tsunami.proto.WebServiceContext;
import java.io.IOException;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executor;
import javax.inject.Inject;
import javax.xml.parsers.ParserConfigurationException;
import org.xml.sax.SAXException;

/** A {@link PortScanner} plugin that uses nmap to scan for open ports and running services. */
@PluginInfo(
    type = PluginType.PORT_SCAN,
    name = "NmapPortScanner",
    version = "0.1",
    description = "Identifies open ports and fingerprints underlying services using nmap.",
    author = "Tsunami Team (tsunami-dev@google.com)",
    bootstrapModule = NmapPortScannerBootstrapModule.class)
public final class NmapPortScanner implements PortScanner {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  private static final int MAX_NUMBER_OF_OS_GUESSES = 1;

  private final NmapClient nmapClient;
  private final Executor commandExecutor;
  private final NmapPortScannerConfigs configs;
  private final NmapPortScannerCliOptions cliOptions;
  private final HttpClientCliOptions httpClientCliOptions;

  private ScanTarget scanTarget;

  @Inject
  NmapPortScanner(
      NmapClient nmapClient,
      @CommandExecutionThreadPool Executor commandExecutor,
      NmapPortScannerConfigs configs,
      NmapPortScannerCliOptions cliOptions,
      HttpClientCliOptions httpClientCliOptions) {
    this.nmapClient = checkNotNull(nmapClient);
    this.commandExecutor = checkNotNull(commandExecutor);
    this.configs = checkNotNull(configs);
    this.cliOptions = checkNotNull(cliOptions);
    this.httpClientCliOptions = checkNotNull(httpClientCliOptions);
  }

  private static boolean isRunningInPrivilegedMode() {
    // TODO(b/353644363): implement proper heuristics for this. For now, autodetection is just
    // turned off.
    return false;
  }

  @Override
  public PortScanningReport scan(ScanTarget scanTarget) {
    this.scanTarget = scanTarget;
    try {
      logger.atInfo().log("Starting nmap scan.");
      Stopwatch stopwatch = Stopwatch.createStarted();
      setPortTargets(nmapClient)
          .withDnsResolution(DnsResolution.NEVER)
          .treatAllHostsAsOnline()
          .withScanTechnique(ScanTechnique.CONNECT)
          .withServiceAndVersionDetection()
          .withVersionDetectionIntensity(5)
          .withScript("banner")
          .withScript("ssl-cert")
          .withScript("ssl-enum-ciphers")
          .withScript("http-methods", "http.useragent=" + httpClientCliOptions.userAgent)
          .withTimingTemplate(TimingTemplate.AGGRESSIVE)
          .withTargetNetworkEndpoint(scanTarget.getNetworkEndpoint())
          .withExtraCommandLineOptions(cliOptions.nmapCmdOpts);

      if (isRunningInPrivilegedMode() || cliOptions.nmapOsDetection) {
        // According to https://nmap.org/book/osdetect-methods.html, OS fingerprinting sends
        // up to 16 packets altogether, so it should not increase the scan time.
        // Also, OS detection requires privileged mode, so we don't set the unprivileged flag.
        nmapClient.withOsDetection().asPrivileged();
      } else {
        nmapClient.asUnprivileged();
      }

      NmapRun result = nmapClient.run(commandExecutor);
      logger.atInfo().log(
          "Finished nmap scan on target '%s' in %s.",
          loggableScanTarget(scanTarget), stopwatch.stop());
      return extractServicesFromNmapRun(result);
    } catch (IOException
        | InterruptedException
        | ExecutionException
        | SAXException
        | ParserConfigurationException e) {
      logger.atSevere().withCause(e).log("Nmap scan failed.");
      return PortScanningReport.newBuilder()
          .setTargetInfo(
              TargetInfo.newBuilder().addNetworkEndpoints(scanTarget.getNetworkEndpoint()))
          .build();
    }
  }

  private NmapClient setPortTargets(NmapClient nmapClient) {
    if (Strings.isNullOrEmpty(configs.portTargets)
        && Strings.isNullOrEmpty(cliOptions.portRangesTarget)) {
      return nmapClient;
    }

    String portTargets =
        (cliOptions.portRangesTarget != null) ? cliOptions.portRangesTarget : configs.portTargets;

    Splitter.on(",")
        .omitEmptyStrings()
        .split(portTargets)
        .forEach(
            portTarget -> {
              TransportProtocol protocol = TransportProtocol.TRANSPORT_PROTOCOL_UNSPECIFIED;
              if (portTarget.length() >= 2 && portTarget.charAt(1) == ':') {
                switch (portTarget.substring(0, 2)) {
                  case "T:":
                    protocol = TransportProtocol.TCP;
                    break;
                  case "U:":
                    protocol = TransportProtocol.UDP;
                    break;
                  case "S:":
                    protocol = TransportProtocol.SCTP;
                    break;
                  default: // fall out
                }
                portTarget = portTarget.substring(2);
              }
              if (portTarget.contains("-")) {
                List<String> rangeSegments = Splitter.on("-").splitToList(portTarget);
                int firstPort = Integer.parseInt(rangeSegments.get(0));
                int lastPort = Integer.parseInt(rangeSegments.get(1));
                if (firstPort == lastPort) {
                  nmapClient.onPort(firstPort, protocol);
                } else {
                  nmapClient.onPortRange(firstPort, lastPort, protocol);
                }
              } else {
                nmapClient.onPort(Integer.parseInt(portTarget), protocol);
              }
            });
    return nmapClient;
  }

  private PortScanningReport extractServicesFromNmapRun(NmapRun nmapRun) {
    logger.atInfo().log("Building PortScanningReport from Nmap result.");
    PortScanningReport.Builder portScanningReportBuilder =
        PortScanningReport.newBuilder().setTargetInfo(buildTargetInfoFromNmaprun(nmapRun));

    Optional<Host> host = getHostFromNmapRun(nmapRun);
    host.flatMap(NmapPortScanner::getPortsFromHost)
        .ifPresent(
            ports ->
                ports.ports().stream()
                    .filter(NmapPortScanner::isPortOpen)
                    .forEach(
                        port -> {
                          NetworkService networkService =
                              buildNetworkService(host.get(), port, null);
                          if (cliOptions.rootPathsTarget != null
                              && NetworkServiceUtils.isWebService(networkService)) {
                            cliOptions.rootPathsTarget.forEach(
                                rootPath -> {
                                  NetworkService webService =
                                      buildNetworkService(host.get(), port, rootPath);
                                  logIdentifiedNetworkService(webService);
                                  portScanningReportBuilder.addNetworkServices(webService);
                                });
                          } else {
                            logIdentifiedNetworkService(networkService);
                            portScanningReportBuilder.addNetworkServices(networkService);
                          }
                        }));
    return portScanningReportBuilder.build();
  }

  private TargetInfo buildTargetInfoFromNmaprun(NmapRun nmapRun) {
    var nmapHost = getHostFromNmapRun(nmapRun);
    var infoBuilder =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(
                nmapHost
                    .map(this::buildNetworkEndpointFromHost)
                    .orElse(scanTarget.getNetworkEndpoint()));
    var oses = buildOperatingSystemClassesFromHost(nmapHost);
    if (!oses.isEmpty()) {
      infoBuilder.addAllOperatingSystemClasses(oses);
    }
    return infoBuilder.build();
  }

  private static OperatingSystemClass convertOperatingSystemClassFromXml(OsClass osc) {
    int accuracy = 0;
    try {
      accuracy = Integer.parseInt(osc.accuracy());
    } catch (NumberFormatException e) {
      logger.atWarning().withCause(e).log("Invalid accuracy value: %s", osc.accuracy());
    }
    return OperatingSystemClass.newBuilder()
        .setType(osc.type())
        .setVendor(osc.vendor())
        .setOsFamily(osc.osFamily())
        .setOsGeneration(osc.osGen())
        .setAccuracy(accuracy)
        .build();
  }

  private ImmutableList<OperatingSystemClass> buildOperatingSystemClassesFromHost(
      Optional<Host> host) {
    if (host.isEmpty()) {
      return ImmutableList.of();
    }
    return host.get().oses().stream()
        .flatMap(os -> os.osMatches().stream())
        .flatMap(osm -> osm.osClasses().stream())
        // Note: we do not order the OSes by accuracy, because Nmap populates the list starting with
        // the "perfect" matches: https://github.com/nmap/nmap/blob/master/output.cc#L1896
        .limit(MAX_NUMBER_OF_OS_GUESSES)
        .map(NmapPortScanner::convertOperatingSystemClassFromXml)
        .collect(toImmutableList());
  }

  private NetworkEndpoint buildNetworkEndpointFromHost(Host host) {
    Optional<Address> address = getAddressFromHost(host);
    Optional<Hostname> hostname = getHostnameFromHost(host);
    String hostnameStr = null;
    if (hostname.isPresent()) {
      hostnameStr = hostname.get().name();
    } else if (NetworkEndpointUtils.hasHostname(scanTarget.getNetworkEndpoint())) {
      // Use the specified hostname if there wasn't returned by the nmap scan. This will be used in
      // HTTP requests even if it doesn't resolve to the same IP as the one scanned.
      hostnameStr = scanTarget.getNetworkEndpoint().getHostname().getName();
    }
    if (address.isPresent() && hostnameStr != null) {
      return NetworkEndpointUtils.forIpAndHostname(address.get().addr(), hostnameStr);
    } else if (address.isPresent()) {
      return NetworkEndpointUtils.forIp(address.get().addr());
    } else if (hostnameStr != null) {
      return NetworkEndpointUtils.forHostname(hostnameStr);
    } else {
      return scanTarget.getNetworkEndpoint();
    }
  }

  private NetworkService buildNetworkService(Host host, Port port, String rootPath) {
    NetworkService.Builder networkServiceBuilder =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                NetworkEndpointUtils.forNetworkEndpointAndPort(
                    buildNetworkEndpointFromHost(host), getPortNumberFromPort(port)))
            .setTransportProtocol(getTransportProtocolFromPort(port));

    if (rootPath != null) {
      networkServiceBuilder.setServiceContext(
          ServiceContext.newBuilder()
              .setWebServiceContext(WebServiceContext.newBuilder().setApplicationRoot(rootPath)));
    }

    getServiceNameFromPort(port).ifPresent(networkServiceBuilder::setServiceName);
    getSoftwareFromPort(port).ifPresent(networkServiceBuilder::setSoftware);
    getCpeFromPort(port).ifPresent(networkServiceBuilder::addAllCpes);
    getSoftwareVersionSetFromPort(port).ifPresent(networkServiceBuilder::setVersionSet);
    getBannerScriptFromPort(port)
        .ifPresent(script -> networkServiceBuilder.addBanner(script.output()));
    getSslVersionsScriptFromPort(port).forEach(networkServiceBuilder::addSupportedSslVersions);
    getHttpMethodsScriptFromPort(port).forEach(networkServiceBuilder::addSupportedHttpMethods);
    return networkServiceBuilder.build();
  }

  private static Optional<Script> getBannerScriptFromPort(Port port) {
    return port.scripts().stream()
        .filter(script -> Ascii.equalsIgnoreCase("banner", Strings.nullToEmpty(script.id())))
        .findFirst();
  }

  private static ImmutableList<String> getSslVersionsScriptFromPort(Port port) {
    return port.scripts().stream()
        .filter(sc -> Ascii.equalsIgnoreCase("ssl-enum-ciphers", Strings.nullToEmpty(sc.id())))
        .flatMap(sc -> sc.tables().stream())
        .map(table -> Ascii.toUpperCase(table.key()))
        .collect(toImmutableList());
  }

  private static ImmutableList<String> getHttpMethodsScriptFromPort(Port port) {
    var httpMethods =
        port.scripts().stream()
            .filter(
                script -> Ascii.equalsIgnoreCase("http-methods", Strings.nullToEmpty(script.id())))
            .flatMap(script -> script.tables().stream())
            .flatMap(table -> table.elems().stream())
            .map(elt -> Ascii.toUpperCase(elt.value()))
            .collect(toImmutableList());

    if (!httpMethods.isEmpty()) {
      return httpMethods;
    }

    // Some server do not support or do not answer to the OPTIONS request (e.g. confluence)
    // sent by nmap's script. In that case, we can still perform a best-effort matching using the
    // "fingerprint-strings" script that is started at the same time.
    var getRequestCount = port.scripts().stream()
        .filter(
            script ->
                Ascii.equalsIgnoreCase("fingerprint-strings", Strings.nullToEmpty(script.id())))
        .flatMap(script -> script.elems().stream())
        .filter(elt -> elt.key().contains("GetRequest"))
        .filter(elt -> elt.value().contains("HTTP/1."))
        .count();

    if (getRequestCount > 0) {
      return ImmutableList.of("GET");
    }

    return ImmutableList.of();
  }

  private static Optional<Host> getHostFromNmapRun(NmapRun nmapRun) {
    return nmapRun.hosts().stream().findFirst();
  }

  private static Optional<Address> getAddressFromHost(Host host) {
    return host.addresses().stream().findFirst();
  }

  private static Optional<Hostname> getHostnameFromHost(Host host) {
    return host.hostnames().stream()
        .flatMap(hostnames -> hostnames.hostnames().stream())
        .findFirst();
  }

  private static Optional<Ports> getPortsFromHost(Host host) {
    return host.ports().stream().findFirst();
  }

  private static boolean isPortOpen(Port port) {
    return Ascii.equalsIgnoreCase("open", Strings.nullToEmpty(port.state().state()));
  }

  private static Optional<Software> getSoftwareFromPort(Port port) {
    return Optional.ofNullable(port.service())
        .map(service -> Strings.emptyToNull(service.product()))
        .map(product -> Software.newBuilder().setName(product).build());
  }

  private static Optional<List<String>> getCpeFromPort(Port port) {
    return Optional.ofNullable(port.service())
        .map(value -> value.cpes().stream().map(Cpe::value).collect(toImmutableList()));
  }

  private static Optional<VersionSet> getSoftwareVersionSetFromPort(Port port) {
    return Optional.ofNullable(port.service())
        .map(service -> Strings.emptyToNull(service.version()))
        .map(
            version ->
                VersionSet.newBuilder()
                    .addVersions(
                        Version.newBuilder()
                            .setType(VersionType.NORMAL)
                            .setFullVersionString(version))
                    .build());
  }

  private static int getPortNumberFromPort(Port port) {
    return Integer.parseInt(port.portId());
  }

  private static TransportProtocol getTransportProtocolFromPort(Port port) {
    return TransportProtocol.valueOf(Ascii.toUpperCase(port.protocol()));
  }

  private static Optional<String> getServiceNameFromPort(Port port) {
    return Optional.ofNullable(port.service())
        .map(
            service -> {
              if (Strings.isNullOrEmpty(service.name())) {
                return null;
              } else if (Strings.isNullOrEmpty(service.tunnel())) {
                return service.name();
              } else {
                return service.tunnel() + "/" + service.name();
              }
            });
  }

  private static void logIdentifiedNetworkService(NetworkService networkService) {
    StringBuilder logMessageBuilder =
        new StringBuilder("Nmap identified service: ip ")
            .append(networkService.getNetworkEndpoint().getIpAddress().getAddress())
            .append(", port ")
            .append(networkService.getNetworkEndpoint().getPort().getPortNumber())
            .append(", protocol ")
            .append(networkService.getTransportProtocol());
    if (!networkService.getServiceName().isEmpty()) {
      logMessageBuilder.append(", service ").append(networkService.getServiceName());
    }
    if (networkService.hasSoftware()) {
      logMessageBuilder.append(", software ").append(networkService.getSoftware().getName());
    }
    if (!networkService.getCpesList().isEmpty()) {
      logMessageBuilder.append(", cpe ").append(String.join(", ", networkService.getCpesList()));
    }
    if (networkService.hasVersionSet()) {
      logMessageBuilder
          .append(", version ")
          .append(networkService.getVersionSet().getVersions(0).getFullVersionString());
    }
    if (!networkService.getBannerList().isEmpty()) {
      logMessageBuilder.append(", banner ").append(networkService.getBanner(0));
    }
    logger.atInfo().log("%s", logMessageBuilder);
  }

  private static String loggableScanTarget(ScanTarget scanTarget) {
    NetworkEndpoint networkEndpoint = scanTarget.getNetworkEndpoint();
    switch (networkEndpoint.getType()) {
      case IP:
        return networkEndpoint.getIpAddress().getAddress();
      case HOSTNAME:
        return networkEndpoint.getHostname().getName();
      case IP_HOSTNAME:
        return networkEndpoint.getIpAddress().getAddress()
            + " / "
            + networkEndpoint.getHostname().getName();
      default:
        throw new AssertionError(
            String.format(
                "Should NEVER happen. Unexpected NetworkEndpoint type for Nmap scan: %s",
                networkEndpoint.getType()));
    }
  }
}
