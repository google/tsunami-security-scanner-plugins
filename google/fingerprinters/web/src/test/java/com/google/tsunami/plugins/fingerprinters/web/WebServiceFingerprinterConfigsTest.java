/*
 * Copyright 2021 Google LLC
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
package com.google.tsunami.plugins.fingerprinters.web;

import static com.google.common.truth.Truth.assertThat;

import com.google.inject.AbstractModule;
import com.google.inject.Guice;
import com.google.tsunami.plugins.fingerprinters.web.WebServiceFingerprinterConfigs.WebServiceFingerprinterCliOptions;
import com.google.tsunami.plugins.fingerprinters.web.WebServiceFingerprinterConfigs.WebServiceFingerprinterConfigProperties;
import javax.inject.Inject;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for {@link WebServiceFingerprinterConfigs}. */
@RunWith(JUnit4.class)
public final class WebServiceFingerprinterConfigsTest {
  private WebServiceFingerprinterCliOptions cliOptions;
  private WebServiceFingerprinterConfigProperties configProperties;

  @Inject WebServiceFingerprinterConfigs configs;

  @Before
  public void setUp() {
    cliOptions = new WebServiceFingerprinterCliOptions();
    configProperties = new WebServiceFingerprinterConfigProperties();
    Guice.createInjector(
            new AbstractModule() {
              @Override
              protected void configure() {
                bind(WebServiceFingerprinterCliOptions.class).toInstance(cliOptions);
                bind(WebServiceFingerprinterConfigProperties.class).toInstance(configProperties);
              }
            })
        .injectMembers(this);
  }

  @Test
  public void shouldEnforceCrawlingScopeCheck_whenCliOptionSetToTrue_returnsTrue() {
    cliOptions.enforceCrawlingScopeCheck = true;
    assertThat(configs.shouldEnforceCrawlingScopeCheck()).isTrue();
  }

  @Test
  public void shouldEnforceCrawlingScopeCheck_whenCliOptionSetToFalse_returnsFalse() {
    cliOptions.enforceCrawlingScopeCheck = false;
    assertThat(configs.shouldEnforceCrawlingScopeCheck()).isFalse();
  }

  @Test
  public void shouldEnforceCrawlingScopeCheck_whenConfigPropertySetToTrue_returnsTrue() {
    configProperties.enforceCrawlingScopeCheck = true;
    assertThat(configs.shouldEnforceCrawlingScopeCheck()).isTrue();
  }

  @Test
  public void shouldEnforceCrawlingScopeCheck_whenConfigPropertySetToFalse_returnsFalse() {
    configProperties.enforceCrawlingScopeCheck = false;
    assertThat(configs.shouldEnforceCrawlingScopeCheck()).isFalse();
  }

  @Test
  public void
      shouldEnforceCrawlingScopeCheck_whenBothCliAndConfigAreSet_cliOptionTakesPrecedence() {
    cliOptions.enforceCrawlingScopeCheck = false;
    configProperties.enforceCrawlingScopeCheck = true;
    assertThat(configs.shouldEnforceCrawlingScopeCheck()).isFalse();
  }

  @Test
  public void shouldEnforceCrawlingScopeCheck_whenBothCliAndConfigAreNotSet_returnsDefaultValue() {
    cliOptions.enforceCrawlingScopeCheck = null;
    configProperties.enforceCrawlingScopeCheck = null;
    assertThat(configs.shouldEnforceCrawlingScopeCheck()).isTrue();
  }
}
