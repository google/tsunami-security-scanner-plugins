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
package com.google.tsunami.plugins.detectors.rce.cve2026123007;

import static com.google.common.truth.Truth.assertThat;

import com.google.common.collect.ImmutableList;
import com.google.inject.Binding;
import com.google.inject.Guice;
import com.google.inject.Injector;
import com.google.inject.TypeLiteral;
import com.google.tsunami.common.data.NetworkEndpointUtils;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.common.net.socket.TsunamiSocketFactoryModule;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.common.time.testing.FakeUtcClockModule;
import com.google.tsunami.plugin.PluginManager;
import com.google.tsunami.plugin.PluginManager.PluginMatchingResult;
import com.google.tsunami.plugin.TsunamiPlugin;
import com.google.tsunami.plugin.VulnDetector;
import com.google.tsunami.plugin.payload.PayloadGeneratorModule;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.ReconnaissanceReport;
import com.google.tsunami.proto.TransportProtocol;
import java.net.InetAddress;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.List;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link Cve2026123007DetectorBootstrapModule}. */
@RunWith(JUnit4.class)
public final class Cve2026123007DetectorBootstrapModuleTest {

  private static final String LOOPBACK_IP = InetAddress.getLoopbackAddress().getHostAddress();

  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2026-11-19T00:00:00Z"));

  @Test
  public void configurePlugin_registersCve2026123007Detector() {
    Injector injector =
        Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new TsunamiSocketFactoryModule(),
            new Cve2026123007DetectorBootstrapModule());

    List<Binding<TsunamiPlugin>> bindings =
        injector.findBindingsByType(TypeLiteral.get(TsunamiPlugin.class));

    assertThat(bindings).hasSize(1);
    assertThat(bindings.get(0).getProvider().get()).isInstanceOf(Cve2026123007Detector.class);
  }

  @Test
  public void pluginManager_routesWebServicesToDetectorAndSkipsNonWebServices() {
    PluginManager pluginManager =
        Guice.createInjector(
                new FakeUtcClockModule(fakeUtcClock),
                new HttpClientModule.Builder().build(),
                new PayloadGeneratorModule(new SecureRandom()),
                new TsunamiSocketFactoryModule(),
                new Cve2026123007DetectorBootstrapModule())
            .getInstance(PluginManager.class);

    NetworkService httpSvc = buildService("http", 8080);
    NetworkService httpsSvc = buildService("https", 8443);
    NetworkService radanHttpSvc = buildService("radan-http", 18088);
    NetworkService tcpwrappedSvc = buildService("tcpwrapped", 8080);
    NetworkService emptyNameSvc = buildService("", 443);
    NetworkService sshSvc = buildService("ssh", 22);

    ReconnaissanceReport reconReport =
        ReconnaissanceReport.newBuilder()
            .addAllNetworkServices(
                ImmutableList.of(
                    httpSvc, httpsSvc, radanHttpSvc, tcpwrappedSvc, emptyNameSvc, sshSvc))
            .build();

    ImmutableList<PluginMatchingResult<VulnDetector>> matched =
        pluginManager.getVulnDetectors(reconReport);

    assertThat(matched).hasSize(1);
    assertThat(matched.get(0).tsunamiPlugin()).isInstanceOf(Cve2026123007Detector.class);
    assertThat(matched.get(0).matchedServices()).containsExactly(httpSvc, httpsSvc, radanHttpSvc);
  }

  private static NetworkService buildService(String serviceName, int port) {
    return NetworkService.newBuilder()
        .setTransportProtocol(TransportProtocol.TCP)
        .setServiceName(serviceName)
        .setNetworkEndpoint(NetworkEndpointUtils.forIpAndPort(LOOPBACK_IP, port))
        .build();
  }
}
