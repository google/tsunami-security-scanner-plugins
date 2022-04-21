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
package com.google.tsunami.plugins.detectors.credentials.ncrack;

import com.google.common.base.Strings;
import com.google.common.collect.ImmutableList;
import com.google.inject.Provides;
import com.google.inject.multibindings.Multibinder;
import com.google.tsunami.plugin.PluginBootstrapModule;
import com.google.tsunami.plugins.detectors.credentials.ncrack.client.NcrackBinaryPath;
import com.google.tsunami.plugins.detectors.credentials.ncrack.client.NcrackClient.TargetService;
import com.google.tsunami.plugins.detectors.credentials.ncrack.client.NcrackExcludedTargetServices;
import com.google.tsunami.plugins.detectors.credentials.ncrack.provider.CredentialProvider;
import com.google.tsunami.plugins.detectors.credentials.ncrack.provider.DefaultCredentials;
import com.google.tsunami.plugins.detectors.credentials.ncrack.provider.Top100Passwords;
import com.google.tsunami.plugins.detectors.credentials.ncrack.tester.CredentialTester;
import java.io.FileNotFoundException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;

/** A {@link PluginBootstrapModule} for {@link NcrackWeakCredentialDetector}. */
public final class NcrackWeakCredentialDetectorBootstrapModule extends PluginBootstrapModule {

  private static final ImmutableList<String> DEFAULT_NCRACK_BINARY_PATHS =
      ImmutableList.of("/usr/bin/ncrack", "/usr/local/bin/ncrack");

  @Override
  protected void configurePlugin() {
    bind(CredentialTester.class).to(NcrackCredentialTester.class);

    Multibinder<CredentialProvider> credentialProviderBinder =
        Multibinder.newSetBinder(binder(), CredentialProvider.class);
    credentialProviderBinder.addBinding().to(Top100Passwords.class);
    credentialProviderBinder.addBinding().to(DefaultCredentials.class);

    registerPlugin(NcrackWeakCredentialDetector.class);
  }

  @Provides
  @NcrackBinaryPath
  String provideNcrackBinaryPath(NcrackWeakCredentialDetectorConfigs configs)
      throws FileNotFoundException {
    if (!Strings.isNullOrEmpty(configs.ncrackBinaryPath)) {
      if (Files.exists(Paths.get(configs.ncrackBinaryPath))) {
        return configs.ncrackBinaryPath;
      }
      throw new FileNotFoundException(
          String.format(
              "Ncrack binary '%s' from config file was not found.", configs.ncrackBinaryPath));
    }

    for (String ncrackBinaryPath : DEFAULT_NCRACK_BINARY_PATHS) {
      if (Files.exists(Paths.get(ncrackBinaryPath))) {
        return ncrackBinaryPath;
      }
    }

    throw new FileNotFoundException(
        "Unable to find a valid ncrack binary. Make sure Tsunami config contains a valid ncrack"
            + " binary path.");
  }

  @Provides
  @NcrackExcludedTargetServices
  List<TargetService> provideNcrackExcludedTargetServices(
      NcrackWeakCredentialDetectorCliOptions cliOptions,
      NcrackWeakCredentialDetectorConfigs configs) {
    if (cliOptions.excludedTargetServices != null && !cliOptions.excludedTargetServices.isEmpty()) {
      return convertToExcludedTargetServices(cliOptions.excludedTargetServices);
    }

    if (configs.excludedTargetServices != null && !configs.excludedTargetServices.isEmpty()) {
      return convertToExcludedTargetServices(configs.excludedTargetServices);
    }

    return ImmutableList.of();
  }

  private static ImmutableList<TargetService> convertToExcludedTargetServices(
      List<String> services) {
    ImmutableList.Builder<TargetService> excludedTargetServices = ImmutableList.builder();

    for (String targetService : services) {
      excludedTargetServices.add(TargetService.valueOf(targetService));
    }

    return excludedTargetServices.build();
  }
}
