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
package com.google.tsunami.plugins.detectors.credentials.ncrack.provider;

import static com.google.common.truth.Truth.assertThat;

import com.google.common.collect.ImmutableList;
import com.google.tsunami.proto.NetworkService;
import java.util.Optional;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for {@link DefaultCredentials}. */
@RunWith(JUnit4.class)
public final class DefaultCredentialsTest {

  private final DefaultCredentials provider = new DefaultCredentials();

  @Test
  public void getName_always_doNotReturnEmptyOrNull() {
    assertThat(provider.name()).isNotEmpty();
    assertThat(provider.name()).isNotNull();
  }

  @Test
  public void getDescription_always_doNotReturnEmptyOrNull() {
    assertThat(provider.description()).isNotEmpty();
    assertThat(provider.description()).isNotNull();
  }

  @Test
  public void genereateTestCredentials_withWordpressServer_returnsExpectedCredentials() {
    ImmutableList<TestCredential> generatedCredentials =
        ImmutableList.copyOf(
            provider.generateTestCredentials(
                NetworkService.newBuilder().setServiceName("WordPress").build()));

    assertThat(generatedCredentials)
        .containsExactly(TestCredential.create("admin", Optional.of("password")));
  }

  @Test
  public void genereateTestCredentials_withUnsupportedService_returnsEmpty() {
    ImmutableList<TestCredential> generatedCredentials =
        ImmutableList.copyOf(provider.generateTestCredentials(NetworkService.getDefaultInstance()));

    assertThat(generatedCredentials).isEmpty();
  }
}
