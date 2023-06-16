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

import com.google.auto.value.AutoValue;
import com.google.errorprone.annotations.Immutable;
import java.util.Optional;

/** Pair of username and password. */
@AutoValue
@Immutable
public abstract class TestCredential {

  public abstract String username();

  public abstract Optional<String> password();

  public static TestCredential create(String username, Optional<String> password) {
    // We do not check for empty strings as they might be valid attempts.
    return new AutoValue_TestCredential(username, password);
  }
}
