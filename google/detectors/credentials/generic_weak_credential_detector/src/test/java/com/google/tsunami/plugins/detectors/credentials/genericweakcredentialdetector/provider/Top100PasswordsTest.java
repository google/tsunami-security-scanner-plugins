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
package com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.provider;

import static com.google.common.truth.Truth.assertThat;

import com.google.common.collect.ImmutableList;
import com.google.tsunami.proto.NetworkService;
import java.util.Optional;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for {@link Top100Passwords}. */
@RunWith(JUnit4.class)
public final class Top100PasswordsTest {

  private static final ImmutableList<String> TEST_USER_NAMES = ImmutableList.of("root", "admin");
  private static final ImmutableList<String> TEST_PASSWORDS = ImmutableList.of("1234", "soleil");
  private static Top100Passwords provider;

  @Before
  public void setupCredentialProvider() {
    provider = new Top100Passwords(TEST_USER_NAMES, TEST_PASSWORDS);
  }

  @Test
  public void defaultConstruct_always_doNotRunOutOfMemoryOrThrows() {
    var unused = new Top100Passwords();
  }

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
  public void genereateTestCredentials_withinExpectedValues_returnsExpectedCredentials() {
    ImmutableList<TestCredential> generatedCredentials =
        ImmutableList.copyOf(provider.generateTestCredentials(NetworkService.getDefaultInstance()));

    assertThat(generatedCredentials)
        .containsExactly(
            TestCredential.create("root", Optional.of("1234")),
            TestCredential.create("root", Optional.of("soleil")),
            TestCredential.create("admin", Optional.of("1234")),
            TestCredential.create("admin", Optional.of("soleil")));
  }
}
