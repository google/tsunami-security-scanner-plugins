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

import com.google.common.base.Ascii;
import com.google.common.base.Splitter;
import com.google.common.base.Stopwatch;
import com.google.common.base.Strings;
import com.google.common.flogger.GoogleLogger;
import com.google.tsunami.common.command.CommandExecutionThreadPool;
import com.google.tsunami.common.data.NetworkEndpointUtils;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.plugin.PluginType;
import com.google.tsunami.plugin.PortScanner;
import com.google.tsunami.plugin.annotations.PluginInfo;
import com.google.tsunami.plugins.portscan.nmap.client.NmapClient;
import com.google.tsunami.plugins.portscan.nmap.client.NmapClient.DnsResolution;
import com.google.tsunami.plugins.portscan.nmap.client.NmapClient.ScanTechnique;
import com.google.tsunami.plugins.portscan.nmap.client.NmapClient.TimingTemplate;
import com.google.tsunami.plugins.portscan.nmap.client.result.Address;
import com.google.tsunami.plugins.portscan.nmap.client.result.Host;
import com.google.tsunami.plugins.portscan.nmap.client.result.Hostname;
import com.google.tsunami.plugins.portscan.nmap.client.result.NmapRun;
import com.google.tsunami.plugins.portscan.nmap.client.result.Port;
import com.google.tsunami.plugins.portscan.nmap.client.result.Ports;
import com.google.tsunami.plugins.portscan.nmap.client.result.Script;
import com.google.tsunami.plugins.portscan.nmap.option.NmapPortScannerCliOptions;
import com.google.tsunami.proto.NetworkEndpoint;
import com.google.tsunami.proto.NetworkService;
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

  private final NmapClient nmapClient;
  private final Executor commandExecutor;
  private final NmapPortScannerConfigs configs;
  private final NmapPortScannerCliOptions cliOptions;

  private ScanTarget scanTarget;

  @Inject
  NmapPortScanner(
      NmapClient nmapClient,
      @CommandExecutionThreadPool Executor commandExecutor,
      NmapPortScannerConfigs configs,
      NmapPortScannerCliOptions cliOptions) {
    this.nmapClient = checkNotNull(nmapClient);
    this.commandExecutor = checkNotNull(commandExecutor);
    this.configs = checkNotNull(configs);
    this.cliOptions = checkNotNull(cliOptions);
  }

  @Override
  public PortScanningReport scan(ScanTarget scanTarget) {
    this.scanTarget = scanTarget;
    try {
      logger.atInfo().log("Starting nmap scan.");
      Stopwatch stopwatch = Stopwatch.createStarted();
      NmapRun result =
          setPortTargets(nmapClient)
              .withDnsResolution(DnsResolution.NEVER)
              .treatAllHostsAsOnline()
              .withScanTechnique(ScanTechnique.CONNECT)
              .asUnprivileged()
              .withServiceAndVersionDetection()
              .withVersionDetectionIntensity(5)
              .withScript("banner")
              .withTimingTemplate(TimingTemplate.AGGRESSIVE)
              .withTargetNetworkEndpoint(scanTarget.getNetworkEndpoint())
              .run(commandExecutor);
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
    return TargetInfo.newBuilder()
        .addNetworkEndpoints(
            getHostFromNmapRun(nmapRun)
                .map(this::buildNetworkEndpointFromHost)
                .orElse(scanTarget.getNetworkEndpoint()))
        .build();
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
    getSoftwareVersionSetFromPort(port).ifPresent(networkServiceBuilder::setVersionSet);
    getBannerScriptFromPort(port)
        .ifPresent(script -> networkServiceBuilder.addBanner(script.output()));
    return networkServiceBuilder.build();
  }

  private static Optional<Script> getBannerScriptFromPort(Port port) {
    return port.scripts().stream()
        .filter(script -> Ascii.equalsIgnoreCase("banner", Strings.nullToEmpty(script.id())))
        .findFirst();
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
    return Optional.ofNullable(port.service()).map(service -> Strings.emptyToNull(service.name()));
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
    if (networkService.hasVersionSet()) {
      logMessageBuilder
          .append(", version ")
          .append(networkService.getVersionSet().getVersions(0).getFullVersionString());
    }
    if (!networkService.getBannerList().isEmpty()) {
      logMessageBuilder.append(", banner ").append(networkService.getBanner(0));
    }
    logger.atInfo().log(logMessageBuilder.toString());
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
