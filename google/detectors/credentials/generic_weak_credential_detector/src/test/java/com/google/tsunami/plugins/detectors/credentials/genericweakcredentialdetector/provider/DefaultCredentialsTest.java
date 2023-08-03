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
package com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.provider;

import static com.google.common.truth.Truth.assertThat;

import com.google.common.collect.ImmutableList;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.proto.DefaultCredentialsData;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.proto.ServiceDefaultCredentials;
import com.google.tsunami.proto.NetworkService;
import java.util.Optional;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for {@link DefaultCredentials}. */
@RunWith(JUnit4.class)
public final class DefaultCredentialsTest {
  private static final DefaultCredentialsData DEFAULT_CREDENTIALS_DATA =
      DefaultCredentialsData.newBuilder()
          .addServiceDefaultCredentials(
              ServiceDefaultCredentials.newBuilder()
                  .setServiceName("wordpress")
                  .addDefaultUsernames("admin")
                  .addDefaultPasswords("password"))
          .addServiceDefaultCredentials(
              ServiceDefaultCredentials.newBuilder()
                  .setServiceName("test")
                  .addDefaultUsernames("user1")
                  .addDefaultUsernames("user2")
                  .addDefaultPasswords("")
                  .addDefaultPasswords("pass1")
                  .addDefaultPasswords("pass2"))
          .build();

  private final DefaultCredentials provider = new DefaultCredentials(DEFAULT_CREDENTIALS_DATA);

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
  public void genereateTestCredentials_withMultiplePairs_returnsExpectedCredentials() {
    ImmutableList<TestCredential> generatedCredentials =
        ImmutableList.copyOf(
            provider.generateTestCredentials(
                NetworkService.newBuilder().setServiceName("test").build()));

    assertThat(generatedCredentials)
        .containsExactly(
            TestCredential.create("user1", Optional.of("")),
            TestCredential.create("user1", Optional.of("pass1")),
            TestCredential.create("user1", Optional.of("pass2")),
            TestCredential.create("user2", Optional.of("")),
            TestCredential.create("user2", Optional.of("pass1")),
            TestCredential.create("user2", Optional.of("pass2")));
  }

  @Test
  public void genereateTestCredentials_withUnsupportedService_returnsEmpty() {
    ImmutableList<TestCredential> generatedCredentials =
        ImmutableList.copyOf(provider.generateTestCredentials(NetworkService.getDefaultInstance()));

    assertThat(generatedCredentials).isEmpty();
  }
}
