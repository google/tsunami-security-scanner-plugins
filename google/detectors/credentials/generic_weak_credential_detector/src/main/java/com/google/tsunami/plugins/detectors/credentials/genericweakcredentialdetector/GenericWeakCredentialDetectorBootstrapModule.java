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
package com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector;

import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.common.base.Strings;
import com.google.common.collect.ImmutableList;
import com.google.common.io.Resources;
import com.google.inject.Provides;
import com.google.inject.multibindings.Multibinder;
import com.google.protobuf.TextFormat;
import com.google.tsunami.common.net.db.ConnectionProvider;
import com.google.tsunami.common.net.db.ConnectionProviderInterface;
import com.google.tsunami.plugin.PluginBootstrapModule;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.clients.hydra.HydraAnnotations.EnableHydra;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.clients.hydra.HydraAnnotations.HydraBinaryPath;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.clients.ncrack.NcrackBinaryPath;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.clients.ncrack.NcrackExcludedTargetServices;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.proto.DefaultCredentialsData;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.proto.TargetService;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.provider.CredentialProvider;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.provider.DefaultCredentials;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.provider.Top100Passwords;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.tester.CredentialTester;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.testers.grafana.GrafanaCredentialTester;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.testers.hydra.HydraCredentialTester;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.testers.jenkins.JenkinsCredentialTester;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.testers.mlflow.MlFlowCredentialTester;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.testers.mysql.MysqlCredentialTester;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.testers.ncrack.NcrackCredentialTester;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.testers.postgres.PostgresCredentialTester;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.testers.rabbitmq.RabbitMQCredentialTester;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.testers.wordpress.WordpressCredentialTester;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.testers.rstudio.RStudioCredentialTester;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;

/** A {@link PluginBootstrapModule} for {@link GenericWeakCredentialDetector}. */
public final class GenericWeakCredentialDetectorBootstrapModule extends PluginBootstrapModule {

  private static final ImmutableList<String> DEFAULT_NCRACK_BINARY_PATHS =
      ImmutableList.of("/usr/bin/ncrack", "/usr/local/bin/ncrack");
  private static final ImmutableList<String> DEFAULT_HYDRA_BINARY_PATHS =
      ImmutableList.of("/usr/bin/hydra", "/usr/local/bin/hydra");

  @Override
  protected void configurePlugin() {

    Multibinder<CredentialTester> credentialTesterBinder =
        Multibinder.newSetBinder(binder(), CredentialTester.class);
    credentialTesterBinder.addBinding().to(JenkinsCredentialTester.class);
    credentialTesterBinder.addBinding().to(MlFlowCredentialTester.class);
    credentialTesterBinder.addBinding().to(MysqlCredentialTester.class);
    credentialTesterBinder.addBinding().to(HydraCredentialTester.class);
    credentialTesterBinder.addBinding().to(NcrackCredentialTester.class);
    credentialTesterBinder.addBinding().to(PostgresCredentialTester.class);
    credentialTesterBinder.addBinding().to(WordpressCredentialTester.class);
    credentialTesterBinder.addBinding().to(GrafanaCredentialTester.class);
    credentialTesterBinder.addBinding().to(RStudioCredentialTester.class);
    credentialTesterBinder.addBinding().to(RabbitMQCredentialTester.class);

    Multibinder<CredentialProvider> credentialProviderBinder =
        Multibinder.newSetBinder(binder(), CredentialProvider.class);
    credentialProviderBinder.addBinding().to(DefaultCredentials.class);
    credentialProviderBinder.addBinding().to(Top100Passwords.class);

    registerPlugin(GenericWeakCredentialDetector.class);
  }

  @Provides
  @NcrackBinaryPath
  String provideNcrackBinaryPath(GenericWeakCredentialDetectorConfigs configs)
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
        "Unable to find a valid ncrack binary. Make sure Tsunami config"
            + " contains a valid ncrack binary path.");
  }

  @Provides
  @EnableHydra
  boolean provideEnableHydra(
      GenericWeakCredentialDetectorCliOptions cliOptions,
      GenericWeakCredentialDetectorConfigs configs) {
    return cliOptions.enableHydra || configs.enableHydra;
  }

  @Provides
  @HydraBinaryPath
  String provideHydraBinaryPath(
      @EnableHydra boolean enableHydra, GenericWeakCredentialDetectorConfigs configs)
      throws FileNotFoundException {
    // Allow hydra to be missing from the environment.
    if (!enableHydra) {
      return "";
    }

    if (!Strings.isNullOrEmpty(configs.hydraBinaryPath)) {
      if (Files.exists(Paths.get(configs.hydraBinaryPath))) {
        return configs.hydraBinaryPath;
      }

      throw new FileNotFoundException(
          String.format(
              "Hydra binary '%s' from config file was not found.", configs.hydraBinaryPath));
    }

    for (String hydraBinaryPath : DEFAULT_HYDRA_BINARY_PATHS) {
      if (Files.exists(Paths.get(hydraBinaryPath))) {
        return hydraBinaryPath;
      }
    }

    throw new FileNotFoundException(
        "Unable to find a valid hydra binary. Make sure Tsunami config"
            + " contains a valid hydra binary path.");
  }

  @Provides
  @NcrackExcludedTargetServices
  List<TargetService> provideNcrackExcludedTargetServices(
      GenericWeakCredentialDetectorCliOptions cliOptions,
      GenericWeakCredentialDetectorConfigs configs) {
    if (cliOptions.excludedTargetServices != null && !cliOptions.excludedTargetServices.isEmpty()) {
      return convertToExcludedTargetServices(cliOptions.excludedTargetServices);
    }

    if (configs.excludedTargetServices != null && !configs.excludedTargetServices.isEmpty()) {
      return convertToExcludedTargetServices(configs.excludedTargetServices);
    }

    return ImmutableList.of();
  }

  @Provides
  DefaultCredentialsData providesDefaultCredentialsData() throws IOException {
    return TextFormat.parse(
        Resources.toString(
            Resources.getResource(
                "detectors/credentials/genericweakcredentialdetector/data/service_default_credentials.textproto"),
            UTF_8),
        DefaultCredentialsData.class);
  }

  @Provides
  ConnectionProviderInterface provideConnectionProvider() {
    return new ConnectionProvider();
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
