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

import java.util.Optional;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for {@link TestCredential}. */
@RunWith(JUnit4.class)
public final class TestCredentialTest {

  @Test
  public void create_withBothUsernameAndPassword_hasValidUsernameAndPassword() {
    TestCredential credential = TestCredential.create("username", Optional.of("password"));

    assertThat(credential.username()).isEqualTo("username");
    assertThat(credential.password()).isEqualTo(Optional.of("password"));
  }

  @Test
  public void create_withEmptyPassword_hasEmptyPassword() {
    TestCredential credential = TestCredential.create("username", Optional.empty());

    assertThat(credential.username()).isEqualTo("username");
    assertThat(credential.password()).isEqualTo(Optional.empty());
  }
}
