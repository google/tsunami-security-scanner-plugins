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
package com.google.tsunami.plugins.detectors.credentials.ncrack;

import static com.google.common.truth.Truth.assertThat;
import static junit.framework.Assert.assertTrue;

import com.google.inject.Guice;
import com.google.tsunami.common.command.CommandExecutorModule;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.common.time.SystemUtcClockModule;
import com.google.tsunami.plugins.detectors.credentials.ncrack.provider.CredentialProvider;
import com.google.tsunami.plugins.detectors.credentials.ncrack.provider.DefaultCredentials;
import com.google.tsunami.plugins.detectors.credentials.ncrack.provider.Top100Passwords;
import javax.inject.Inject;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for {@link NcrackWeakCredentialDetectorBootstrapModule}. */
@RunWith(JUnit4.class)
public final class NcrackWeakCredentialDetectorBootstrapModuleTest {

  @Inject private NcrackWeakCredentialDetector detector;

  @Before
  public void setUp() {
    Guice.createInjector(
            new CommandExecutorModule(),
            new HttpClientModule.Builder().build(),
            new SystemUtcClockModule(),
            new NcrackWeakCredentialDetectorBootstrapModule())
        .injectMembers(this);
  }

  @Test
  public void detector_hasImplimentedCredentialProviders() {
    assertThat(detector.providers).hasSize(2);
    for (CredentialProvider provider : detector.providers) {
      assertTrue(provider instanceof DefaultCredentials || provider instanceof Top100Passwords);
    }
  }
}
