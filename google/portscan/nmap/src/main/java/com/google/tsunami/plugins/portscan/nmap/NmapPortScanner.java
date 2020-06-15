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
import com.google.tsunami.plugin.PluginType;
import com.google.tsunami.plugin.PortScanner;
import com.google.tsunami.plugin.annotations.PluginInfo;
import com.google.tsunami.plugins.portscan.nmap.client.NmapClient;
import com.google.tsunami.plugins.portscan.nmap.client.NmapClient.DnsResolution;
import com.google.tsunami.plugins.portscan.nmap.client.NmapClient.ScanTechnique;
import com.google.tsunami.plugins.portscan.nmap.client.NmapClient.TimingTemplate;
import com.google.tsunami.plugins.portscan.nmap.client.data.xml.Address;
import com.google.tsunami.plugins.portscan.nmap.client.data.xml.Host;
import com.google.tsunami.plugins.portscan.nmap.client.data.xml.Hostname;
import com.google.tsunami.plugins.portscan.nmap.client.data.xml.Nmaprun;
import com.google.tsunami.plugins.portscan.nmap.client.data.xml.Port;
import com.google.tsunami.plugins.portscan.nmap.client.data.xml.Ports;
import com.google.tsunami.plugins.portscan.nmap.client.data.xml.Script;
import com.google.tsunami.plugins.portscan.nmap.client.data.xml.Service;
import com.google.tsunami.proto.NetworkEndpoint;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.PortScanningReport;
import com.google.tsunami.proto.ScanTarget;
import com.google.tsunami.proto.Software;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.TransportProtocol;
import com.google.tsunami.proto.Version;
import com.google.tsunami.proto.Version.VersionType;
import com.google.tsunami.proto.VersionSet;
import java.io.IOException;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executor;
import javax.inject.Inject;
import javax.xml.bind.JAXBException;

/** A {@link PortScanner} plugin that uses nmap to scan for open ports and running services. */
@PluginInfo(
    type = PluginType.PORT_SCAN,
    name = "NmapPortScanner",
    version = "0.1",
    description = "Identifies open ports and fingerprints underlying services using nmap.",
    author = "Tsunami Dev (tsunami-dev@google.com)",
    bootstrapModule = NmapPortScannerBootstrapModule.class)
public final class NmapPortScanner implements PortScanner {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private final NmapClient nmapClient;
  private final Executor commandExecutor;
  private final NmapPortScannerConfigs configs;

  private ScanTarget scanTarget;

  @Inject
  NmapPortScanner(
      NmapClient nmapClient,
      @CommandExecutionThreadPool Executor commandExecutor,
      NmapPortScannerConfigs configs) {
    this.nmapClient = checkNotNull(nmapClient);
    this.commandExecutor = checkNotNull(commandExecutor);
    this.configs = checkNotNull(configs);
  }

  @Override
  public PortScanningReport scan(ScanTarget scanTarget) {
    this.scanTarget = scanTarget;
    try {
      logger.atInfo().log("Starting nmap scan.");
      Stopwatch stopwatch = Stopwatch.createStarted();
      Nmaprun result =
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
    } catch (IOException | JAXBException | InterruptedException | ExecutionException e) {
      logger.atSevere().withCause(e).log("Nmap scan failed.");
      return PortScanningReport.newBuilder()
          .setTargetInfo(
              TargetInfo.newBuilder().addNetworkEndpoints(scanTarget.getNetworkEndpoint()))
          .build();
    }
  }

  private NmapClient setPortTargets(NmapClient nmapClient) {
    if (Strings.isNullOrEmpty(configs.portTargets)) {
      return nmapClient;
    }

    Splitter.on(",")
        .omitEmptyStrings()
        .split(configs.portTargets)
        .forEach(
            portTarget -> {
              if (portTarget.contains("-")) {
                List<String> rangeSegments = Splitter.on("-").splitToList(portTarget);
                nmapClient.onPortRange(
                    Integer.parseInt(rangeSegments.get(0)), Integer.parseInt(rangeSegments.get(1)));
              } else {
                nmapClient.onPort(Integer.parseInt(portTarget));
              }
            });
    return nmapClient;
  }

  private PortScanningReport extractServicesFromNmapRun(Nmaprun nmaprun) {
    logger.atInfo().log("Building PortScanningReport from Nmap result.");
    PortScanningReport.Builder portScanningReportBuilder =
        PortScanningReport.newBuilder().setTargetInfo(buildTargetInfoFromNmaprun(nmaprun));

    Optional<Host> host = getHostFromNmapRun(nmaprun);
    host.flatMap(NmapPortScanner::getPortsFromHost)
        .ifPresent(
            ports ->
                ports.getPort().stream()
                    .filter(NmapPortScanner::isPortOpen)
                    .forEach(
                        port -> {
                          NetworkService networkService = buildNetworkService(host.get(), port);
                          logIdentifiedNetworkService(networkService);
                          portScanningReportBuilder.addNetworkServices(networkService);
                        }));
    return portScanningReportBuilder.build();
  }

  private TargetInfo buildTargetInfoFromNmaprun(Nmaprun nmaprun) {
    return TargetInfo.newBuilder()
        .addNetworkEndpoints(
            getHostFromNmapRun(nmaprun)
                .map(this::buildNetworkEndpointFromHost)
                .orElse(scanTarget.getNetworkEndpoint()))
        .build();
  }

  private NetworkEndpoint buildNetworkEndpointFromHost(Host host) {
    Optional<Address> address = getAddressFromHost(host);
    Optional<Hostname> hostname = getHostnameFromHost(host);
    if (address.isPresent()) {
      return NetworkEndpointUtils.forIp(address.get().getAddr());
    } else if (hostname.isPresent()) {
      return NetworkEndpointUtils.forHostname(hostname.get().getName());
    } else {
      return scanTarget.getNetworkEndpoint();
    }
  }

  private NetworkService buildNetworkService(Host host, Port port) {
    NetworkService.Builder networkServiceBuilder =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                NetworkEndpointUtils.forNetworkEndpointAndPort(
                    buildNetworkEndpointFromHost(host), getPortNumberFromPort(port)))
            .setTransportProtocol(getTransportProtocolFromPort(port));

    getServiceNameFromPort(port).ifPresent(networkServiceBuilder::setServiceName);
    getSoftwareFromPort(port).ifPresent(networkServiceBuilder::setSoftware);
    getSoftwareVersionSetFromPort(port).ifPresent(networkServiceBuilder::setVersionSet);
    getBannerScriptFromPort(port)
        .ifPresent(script -> networkServiceBuilder.addBanner(script.getOutput()));
    return networkServiceBuilder.build();
  }

  private static Optional<Script> getBannerScriptFromPort(Port port) {
    return port.getScript().stream()
        .filter(script -> Ascii.equalsIgnoreCase("banner", Strings.nullToEmpty(script.getId())))
        .findFirst();
  }

  private static Optional<Host> getHostFromNmapRun(Nmaprun nmaprun) {
    return nmaprun
        .getTargetOrTaskbeginOrTaskprogressOrTaskendOrPrescriptOrPostscriptOrHostOrOutput()
        .stream()
        .filter(el -> el instanceof Host)
        .findFirst()
        .map(Host.class::cast);
  }

  private static Optional<Address> getAddressFromHost(Host host) {
    return host
        .getStatusOrAddressOrHostnamesOrSmurfOrPortsOrOsOrDistanceOrUptimeOrTcpsequenceOrIpidsequenceOrTcptssequenceOrHostscriptOrTraceOrTimes()
        .stream()
        .filter(el -> el instanceof Address)
        .findFirst()
        .map(Address.class::cast);
  }

  private static Optional<Hostname> getHostnameFromHost(Host host) {
    return host
        .getStatusOrAddressOrHostnamesOrSmurfOrPortsOrOsOrDistanceOrUptimeOrTcpsequenceOrIpidsequenceOrTcptssequenceOrHostscriptOrTraceOrTimes()
        .stream()
        .filter(el -> el instanceof Hostname)
        .findFirst()
        .map(Hostname.class::cast);
  }

  private static Optional<Ports> getPortsFromHost(Host host) {
    return host
        .getStatusOrAddressOrHostnamesOrSmurfOrPortsOrOsOrDistanceOrUptimeOrTcpsequenceOrIpidsequenceOrTcptssequenceOrHostscriptOrTraceOrTimes()
        .stream()
        .filter(el -> el instanceof Ports)
        .findFirst()
        .map(Ports.class::cast);
  }

  private static boolean isPortOpen(Port port) {
    return port.getState().getState().equals("open");
  }

  private static Optional<Software> getSoftwareFromPort(Port port) {
    return Optional.ofNullable(port.getService())
        .map(Service::getProduct)
        .map(product -> Software.newBuilder().setName(product).build());
  }

  private static Optional<VersionSet> getSoftwareVersionSetFromPort(Port port) {
    return Optional.ofNullable(port.getService())
        .map(Service::getVersion)
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
    return Integer.parseInt(port.getPortid());
  }

  private static TransportProtocol getTransportProtocolFromPort(Port port) {
    return TransportProtocol.valueOf(Ascii.toUpperCase(port.getProtocol()));
  }

  private static Optional<String> getServiceNameFromPort(Port port) {
    return Optional.ofNullable(port.getService()).map(Service::getName);
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
      default:
        throw new AssertionError(
            String.format(
                "Should NEVER happen. Unexpected NetworkEndpoint type for Nmap scan: %s",
                networkEndpoint.getType()));
    }
  }
}
