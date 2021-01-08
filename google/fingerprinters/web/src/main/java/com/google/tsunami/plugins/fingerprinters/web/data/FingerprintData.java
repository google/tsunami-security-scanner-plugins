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

import com.google.auto.value.AutoValue;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.Maps;
import com.google.tsunami.plugins.fingerprinters.web.proto.ContentHash;
import com.google.tsunami.plugins.fingerprinters.web.proto.Fingerprints;
import com.google.tsunami.plugins.fingerprinters.web.proto.Hash;
import com.google.tsunami.plugins.fingerprinters.web.proto.HashVersion;
import com.google.tsunami.plugins.fingerprinters.web.proto.PathVersion;
import com.google.tsunami.plugins.fingerprinters.web.proto.SoftwareIdentity;

/** A Java POJO wrapper around the {@link Fingerprints} proto message. */
@AutoValue
public abstract class FingerprintData {
  public abstract SoftwareIdentity softwareIdentity();
  public abstract ImmutableMap<String, ContentHash> contentHashes();
  public abstract ImmutableMap<Hash, HashVersion> hashVersions();

  public abstract ImmutableMap<String, PathVersion> pathVersions();

  public static FingerprintData fromProto(Fingerprints fingerprints) {
    checkNotNull(fingerprints);
    ImmutableMap<String, ContentHash> contentHashes =
        Maps.uniqueIndex(fingerprints.getContentHashesList(), ContentHash::getContentPath);
    ImmutableMap<Hash, HashVersion> hashVersions =
        Maps.uniqueIndex(fingerprints.getHashVersionsList(), HashVersion::getHash);
    ImmutableMap<String, PathVersion> pathVersions =
        Maps.uniqueIndex(fingerprints.getPathVersionsList(), PathVersion::getContentPath);
    return new com.google.tsunami.plugins.fingerprinters.web.data.AutoValue_FingerprintData(
        fingerprints.getSoftwareIdentity(), contentHashes, hashVersions, pathVersions);
  }
}
