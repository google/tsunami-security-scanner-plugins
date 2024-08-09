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
package com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.testers.ncrack;

import static com.google.common.base.Preconditions.checkNotNull;

import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.Multimap;
import com.google.common.flogger.GoogleLogger;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.google.tsunami.common.command.CommandExecutionThreadPool;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.clients.ncrack.NcrackClient;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.clients.ncrack.NcrackClient.TimingTemplate;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.clients.ncrack.NcrackExcludedTargetServices;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.clients.ncrack.data.NcrackRun;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.proto.TargetService;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.provider.TestCredential;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.tester.CredentialTester;
import com.google.tsunami.proto.NetworkService;
import java.io.IOException;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executor;
import javax.inject.Inject;
import javax.inject.Provider;

/**
 * Credential tester using the ncrack brute forcer. See {@link NcrackCredentialTester#SERVICE_MAP}
 * for list of supported services.
 */
public final class NcrackCredentialTester extends CredentialTester {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  /**
   * Each target is a dedicated module located <a
   * href="https://github.com/nmap/ncrack/tree/master/modules">here</a>. * *
   *
   * <p>For extra documentation on each module, its expected performance and extra flags it
   * supports, check <a herf="https://nmap.org/ncrack/man.html">modules documentation</a>.
   *
   * <p>IMPORTANT: list of supported modules is actively updated. Check Github link above to see the
   * * list of current modules. Experimental modules, like Web Form are not added to the list.
   */
  private static final ImmutableMap<String, TargetService> SERVICE_MAP =
      ImmutableMap.<String, TargetService>builder()
          // Missing from TargetService: JOOMLA, HTTP, OWA
          .put("cassandra", TargetService.CASSANDRA)
          .put("ssh", TargetService.SSH)
          .put("ftp", TargetService.FTP)
          .put("wordpress", TargetService.WORDPRESS)
          .put("telnet", TargetService.TELNET)
          .put("pop3", TargetService.POP3)
          .put("imap", TargetService.IMAP)
          .put("cvspserver", TargetService.CVS)
          .put("netbios-ssn", TargetService.SMB)
          .put("microsoft-ds", TargetService.SMB2)
          .put("vnc", TargetService.VNC)
          .put("sip", TargetService.SIP)
          .put("redis", TargetService.REDIS)
          .put("ms-sql-s", TargetService.MSSQL)
          .put("mqtt", TargetService.MQTT)
          .put("mongod", TargetService.MONGODB)
          .put("mongodb", TargetService.MONGODB)
          .put("winrm", TargetService.WINRM)
          .put("dicom", TargetService.DICOM)
          .build();

  private final Provider<NcrackClient> ncrackClientProvider;
  private final Executor executor;
  private final List<TargetService> excludedTargetServices;

  @Inject
  NcrackCredentialTester(
      Provider<NcrackClient> ncrackClientProvider,
      @CommandExecutionThreadPool Executor executor,
      @NcrackExcludedTargetServices List<TargetService> excludedTargetServices) {
    this.ncrackClientProvider = checkNotNull(ncrackClientProvider);
    this.executor = checkNotNull(executor);
    this.excludedTargetServices = checkNotNull(excludedTargetServices);
  }

  @Override
  public String name() {
    return "NcrackCredentialTester";
  }

  @Override
  public String description() {
    return String.format(
        "Ncrack credential tester supporting the following services: %s",
        String.join(", ", SERVICE_MAP.keySet()));
  }

  @Override
  public boolean canAccept(NetworkService networkService) {
    String serviceName = NetworkServiceUtils.getServiceName(networkService);
    return SERVICE_MAP.containsKey(serviceName)
        && !excludedTargetServices.contains(SERVICE_MAP.get(serviceName));
  }

  @Override
  public boolean batched() {
    return true;
  }

  @Override
  @CanIgnoreReturnValue
  public ImmutableList<TestCredential> testValidCredentials(
      NetworkService networkService, List<TestCredential> credentials) {
    if (!canAccept(networkService)) {
      return ImmutableList.of();
    }

    try {
      // We use a Provider here to get a new NcrackClient object because this function might be
      // called multiple times in the client code.
      NcrackRun result =
          ncrackClientProvider
              .get()
              .withTimingTemplate(TimingTemplate.NORMAL)
              .withQuitCrackingAfterOneFound()
              .withNetworkEndpoint(networkService.getNetworkEndpoint())
              .usingUsernamePasswordPair(
                  generateTestCredentialsMapFromListOfCredentials(credentials))
              .onTargetService(getTargetService(networkService))
              .run(this.executor);

      return result.discoveredCredentials().stream()
          .filter(discoveredCredential -> discoveredCredential.username().isPresent())
          .map(
              discoveredCredential ->
                  TestCredential.create(
                      discoveredCredential.username().get(), discoveredCredential.password()))
          .collect(ImmutableList.toImmutableList());
    } catch (IOException | InterruptedException | ExecutionException e) {
      logger.atSevere().withCause(e).log("Error executing ncrack.");
      return ImmutableList.of();
    }
  }

  private static TargetService getTargetService(NetworkService networkService) {
    return SERVICE_MAP.get(NetworkServiceUtils.getServiceName(networkService));
  }

  private static Multimap<String, String> generateTestCredentialsMapFromListOfCredentials(
      List<TestCredential> credentials) {
    Multimap<String, String> map = ArrayListMultimap.create();
    credentials.forEach(c -> map.put(c.username(), c.password().orElse("")));
    return map;
  }
}
