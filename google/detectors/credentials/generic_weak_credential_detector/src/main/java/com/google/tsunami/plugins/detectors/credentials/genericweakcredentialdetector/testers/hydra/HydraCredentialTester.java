/*
 * Copyright 2023 Google LLC
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
package com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.testers.hydra;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;

import com.google.common.base.Ascii;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.flogger.GoogleLogger;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.clients.hydra.HydraClient;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.clients.hydra.data.HydraRun;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.proto.TargetService;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.provider.TestCredential;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.tester.CredentialTester;
import com.google.tsunami.proto.NetworkService;
import java.io.IOException;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.ExecutionException;
import javax.inject.Inject;
import javax.inject.Provider;

/**
 * Credential tester using the hydra brute forcer. See {@link HydraCredentialTester#SERVICE_MAP} for
 * list of supported services.
 */
public final class HydraCredentialTester extends CredentialTester {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  /**
   * Hydra supported services can be found <a
   * href="https://github.com/vanhauser-thc/thc-hydra">here</a>.
   */
  private static final ImmutableMap<String, TargetService> SERVICE_MAP =
      ImmutableMap.of("ms-wbt-server", TargetService.RDP);

  private final Provider<HydraClient> hydraClientProvider;

  @Inject
  HydraCredentialTester(Provider<HydraClient> hydraClientProvider) {
    this.hydraClientProvider = checkNotNull(hydraClientProvider);
  }

  @Override
  public String name() {
    return "HydraCredentialTester";
  }

  @Override
  public String description() {
    return String.format(
        "Hydra credential tester supporting the following services: %s",
        String.join(", ", SERVICE_MAP.keySet()));
  }

  @Override
  public boolean canAccept(NetworkService networkService) {
    if (!hydraClientProvider.get().isEnableHydra()) {
      return false;
    }
    String serviceName = NetworkServiceUtils.getServiceName(networkService);
    String softwareName = Ascii.toLowerCase(networkService.getSoftware().getName());

    // TODO(b/311336843): Temporary hack to filter out false positives when scanning xrdp service
    return SERVICE_MAP.containsKey(serviceName) && !Objects.equals(softwareName, "xrdp");
  }

  // Hydra performs better by managing the threads internally to enforce the rate limit
  @Override
  public boolean batched() {
    return false;
  }

  @Override
  @CanIgnoreReturnValue
  public ImmutableList<TestCredential> testValidCredentials(
      NetworkService networkService, List<TestCredential> credentials) {
    if (!canAccept(networkService)) {
      return ImmutableList.of();
    }

    try {
      // We use a Provider here to get a new HydraClient object because this function might be
      // called multiple times in the client code.
      HydraRun result =
          hydraClientProvider
              .get()
              .withNetworkEndpoint(networkService.getNetworkEndpoint())
              .usingUsernamePasswordPair(credentials)
              .onTargetService(getTargetService(networkService))
              .run();

      ImmutableList<TestCredential> weakCreds =
          result.discoveredCredentials().stream()
              .filter(discoveredCredential -> discoveredCredential.username().isPresent())
              .map(
                  discoveredCredential ->
                      TestCredential.create(
                          discoveredCredential.username().get(), discoveredCredential.password()))
              .collect(toImmutableList());

      // TODO(b/311336843): Temporary hack to filter out false positives when scanning xrdp service
      // More info see: https://github.com/vanhauser-thc/thc-hydra/issues/923
      // 3 is an arbitrary number, it just need to be sufficiently large to indicate there's a
      // potential issue. This hack also misses rdp service without auth.
      if (weakCreds.size() > 3) {
        return ImmutableList.of();
      } else {
        return weakCreds;
      }
    } catch (IOException | InterruptedException | ExecutionException e) {
      logger.atSevere().withCause(e).log("Error executing hydra.");
      return ImmutableList.of();
    }
  }

  private static TargetService getTargetService(NetworkService networkService) {
    return SERVICE_MAP.get(NetworkServiceUtils.getServiceName(networkService));
  }
}
