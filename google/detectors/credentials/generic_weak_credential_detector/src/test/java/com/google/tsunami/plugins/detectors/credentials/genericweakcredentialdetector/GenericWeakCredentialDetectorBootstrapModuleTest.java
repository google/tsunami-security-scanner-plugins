/*
 * Copyright 2022 Google LLC
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

import static com.google.common.truth.Truth.assertThat;
import static junit.framework.Assert.assertTrue;
import static org.junit.Assert.assertThrows;

import com.google.common.collect.ImmutableList;
import com.google.inject.AbstractModule;
import com.google.inject.Guice;
import com.google.tsunami.common.command.CommandExecutorModule;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.common.time.SystemUtcClockModule;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.proto.TargetService;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.provider.CredentialProvider;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.provider.DefaultCredentials;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.provider.Top100Passwords;
import javax.inject.Inject;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for {@link GenericWeakCredentialDetectorBootstrapModule}. */
@RunWith(JUnit4.class)
public final class GenericWeakCredentialDetectorBootstrapModuleTest {

  @Inject private GenericWeakCredentialDetector detector;
  private final GenericWeakCredentialDetectorBootstrapModule module =
      new GenericWeakCredentialDetectorBootstrapModule();
  private final GenericWeakCredentialDetectorConfigs configs =
      new GenericWeakCredentialDetectorConfigs();
  private final GenericWeakCredentialDetectorCliOptions cliOptions =
      new GenericWeakCredentialDetectorCliOptions();

  @Before
  public void setUp() {
    Guice.createInjector(
            new CommandExecutorModule(),
            new HttpClientModule.Builder().build(),
            new SystemUtcClockModule(),
            module,
            new AbstractModule() {
              @Override
              protected void configure() {
                bind(GenericWeakCredentialDetectorConfigs.class).toInstance(configs);
                bind(GenericWeakCredentialDetectorCliOptions.class).toInstance(cliOptions);
              }
            })
        .injectMembers(this);
  }

  @Test
  public void detector_hasImplimentedCredentialProviders() {
    assertThat(detector.providers).hasSize(2);
    for (CredentialProvider provider : detector.providers) {
      assertTrue(provider instanceof DefaultCredentials || provider instanceof Top100Passwords);
    }
  }

  @Test
  public void provideExcludedTargetServicesStrings_configsOnly_returnsExcludedTargetServices() {
    configs.excludedTargetServices = ImmutableList.of("SSH", "IMAP");
    assertThat(module.provideNcrackExcludedTargetServices(cliOptions, configs))
        .containsExactly(TargetService.SSH, TargetService.IMAP);
  }

  @Test
  public void
      provideInvalidExcludedTargetServicesStrings_configsOnly_throwsIllegalArgumentException() {
    configs.excludedTargetServices = ImmutableList.of("ssh");
    assertThrows(
        IllegalArgumentException.class,
        () -> module.provideNcrackExcludedTargetServices(cliOptions, configs));
  }

  @Test
  public void
      provideExcludedTargetServicesStrings_configsAndCliOptions_returnsExcludedTargetServicesFromCliOptions() {
    configs.excludedTargetServices = ImmutableList.of("SSH");
    cliOptions.excludedTargetServices = ImmutableList.of("IMAP");
    assertThat(module.provideNcrackExcludedTargetServices(cliOptions, configs))
        .contains(TargetService.IMAP);
  }
}
