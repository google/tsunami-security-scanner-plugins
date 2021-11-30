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
package com.google.tsunami.plugins.fingerprinters.web.data;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableSet.toImmutableSet;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.google.tsunami.plugins.fingerprinters.web.proto.Hash;
import com.google.tsunami.plugins.fingerprinters.web.proto.SoftwareIdentity;
import java.util.Map;
import java.util.Optional;
import javax.inject.Inject;

/** A registry of all web fingerprints data. */
public final class FingerprintRegistry {

  private final ImmutableMap<SoftwareIdentity, FingerprintData> fingerprintsData;

  @Inject
  FingerprintRegistry(ImmutableMap<SoftwareIdentity, FingerprintData> fingerprintsData) {
    this.fingerprintsData = checkNotNull(fingerprintsData);
  }

  public ImmutableSet<SoftwareIdentity> allSoftware() {
    return fingerprintsData.keySet();
  }

  public ImmutableSet<SoftwareIdentity> matchSoftwareForHash(Hash hash) {
    return fingerprintsData.entrySet().stream()
        .filter(entry -> entry.getValue().hashVersions().containsKey(hash))
        .map(Map.Entry::getKey)
        .collect(toImmutableSet());
  }

  public Optional<FingerprintData> getFingerprintData(SoftwareIdentity softwareIdentity) {
    return Optional.ofNullable(fingerprintsData.get(softwareIdentity));
  }

  /**
   * Returns true if there's only a single software in the fingerprints that has {@code hash} among
   * its static file hashes. Files used by several different software are likely shared libraries.
   */
  public boolean isGloballyUniqueHash(Hash hash) {
    return fingerprintsData.values().stream()
            .filter(fingerprintData -> fingerprintData.hashVersions().containsKey(hash))
            .count()
        <= 1;
  }

  /**
   * Returns true if there's only a single software in the fingerprints that has {@code path} among
   * its static file paths. Files used by several different software are likely shared libraries.
   */
  public boolean isGloballyUniquePath(String path) {
    return fingerprintsData.values().stream()
            .filter(fingerprintData -> fingerprintData.pathVersions().containsKey(path))
            .count()
        <= 1;
  }
}
