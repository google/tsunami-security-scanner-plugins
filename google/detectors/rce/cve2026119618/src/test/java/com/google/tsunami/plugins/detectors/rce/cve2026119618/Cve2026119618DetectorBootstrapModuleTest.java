/*
 * Copyright 2026 Google LLC
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
package com.google.tsunami.plugins.detectors.rce.cve2026119618;

import static com.google.common.truth.Truth.assertThat;

import com.google.common.collect.ImmutableList;
import com.google.inject.Binding;
import com.google.inject.Guice;
import com.google.inject.Injector;
import com.google.inject.TypeLiteral;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.common.net.socket.TsunamiSocketFactoryModule;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.common.time.testing.FakeUtcClockModule;
import com.google.tsunami.plugin.PluginManager;
import com.google.tsunami.plugin.PluginManager.PluginMatchingResult;
import com.google.tsunami.plugin.TsunamiPlugin;
import com.google.tsunami.plugin.VulnDetector;
import com.google.tsunami.plugin.payload.PayloadGeneratorModule;
import com.google.tsunami.proto.IpAddress;
import com.google.tsunami.proto.NetworkEndpoint;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.Port;
import com.google.tsunami.proto.ReconnaissanceReport;
import com.google.tsunami.proto.TransportProtocol;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.List;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link Cve2026119618DetectorBootstrapModule}. */
@RunWith(JUnit4.class)
public final class Cve2026119618DetectorBootstrapModuleTest {

  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2026-11-14T05:00:00.00Z"));

  @Test
  public void configurePlugin_registersCve2026119618Detector() {
    Injector injector =
        Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new TsunamiSocketFactoryModule(),
            new Cve2026119618DetectorBootstrapModule());

    List<Binding<TsunamiPlugin>> bindings =
        injector.findBindingsByType(TypeLiteral.get(TsunamiPlugin.class));

    assertThat(bindings).hasSize(1);
    assertThat(bindings.get(0).getProvider().get()).isInstanceOf(Cve2026119618Detector.class);
  }

  @Test
  public void pluginManager_routesWebAndWrappedServicesToDetectorAndSkipsUnrelatedServices() {
    PluginManager pluginManager =
        Guice.createInjector(
                new FakeUtcClockModule(fakeUtcClock),
                new HttpClientModule.Builder().build(),
                new PayloadGeneratorModule(new SecureRandom()),
                new TsunamiSocketFactoryModule(),
                new Cve2026119618DetectorBootstrapModule())
            .getInstance(PluginManager.class);

    NetworkService httpSvc = service("http", 8080);
    NetworkService httpsSvc = service("https", 8443);
    NetworkService httpOverSslSvc = service("http over ssl", 9443);
    NetworkService tcpwrappedSvc = service("tcpwrapped", 8080);
    NetworkService emptyNameSvc = service("", 443);
    NetworkService sshSvc = service("ssh", 22);

    ReconnaissanceReport reconReport =
        ReconnaissanceReport.newBuilder()
            .addAllNetworkServices(
                ImmutableList.of(
                    httpSvc, httpsSvc, httpOverSslSvc, tcpwrappedSvc, emptyNameSvc, sshSvc))
            .build();

    ImmutableList<PluginMatchingResult<VulnDetector>> matched =
        pluginManager.getVulnDetectors(reconReport);

    assertThat(matched).hasSize(1);
    assertThat(matched.get(0).tsunamiPlugin()).isInstanceOf(Cve2026119618Detector.class);
    assertThat(matched.get(0).matchedServices())
        .containsExactly(httpSvc, httpsSvc, httpOverSslSvc, tcpwrappedSvc, emptyNameSvc);
  }

  private static NetworkService service(String serviceName, int port) {
    return NetworkService.newBuilder()
        .setTransportProtocol(TransportProtocol.TCP)
        .setServiceName(serviceName)
        .setNetworkEndpoint(
            NetworkEndpoint.newBuilder()
                .setIpAddress(IpAddress.newBuilder().setAddress("127.0.0.1"))
                .setPort(Port.newBuilder().setPortNumber(port)))
        .build();
  }
}
