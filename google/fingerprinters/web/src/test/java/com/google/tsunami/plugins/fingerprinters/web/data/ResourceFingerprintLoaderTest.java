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

import static com.google.common.truth.Truth.assertThat;

import com.google.tsunami.plugins.fingerprinters.web.proto.ContentHash;
import com.google.tsunami.plugins.fingerprinters.web.proto.Fingerprints;
import com.google.tsunami.plugins.fingerprinters.web.proto.Hash;
import com.google.tsunami.plugins.fingerprinters.web.proto.HashVersion;
import com.google.tsunami.plugins.fingerprinters.web.proto.PathVersion;
import com.google.tsunami.plugins.fingerprinters.web.proto.SoftwareIdentity;
import com.google.tsunami.plugins.fingerprinters.web.proto.Version;
import io.github.classgraph.ClassGraph;
import io.github.classgraph.ScanResult;
import java.io.IOException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for {@link ResourceFingerprintLoader}. */
@RunWith(JUnit4.class)
public final class ResourceFingerprintLoaderTest {

  @Test
  public void loadFingerprints_whenNoFingerprintData_returnsEmptySet() throws IOException {
    try (ScanResult scanResult =
        new ClassGraph().enableAllInfo().whitelistPaths("/not/exist").scan()) {
      assertThat(new ResourceFingerprintLoader(scanResult).loadFingerprints()).isEmpty();
    }
  }

  @Test
  public void loadFingerprints_whenValidFingerprintData_returnsLoadedFingerprints()
      throws IOException {
    try (ScanResult scanResult =
        new ClassGraph()
            .enableAllInfo()
            .whitelistPaths("com/google/tsunami/plugins/fingerprinters/web/data/testdata")
            .scan()) {
      assertThat(new ResourceFingerprintLoader(scanResult).loadFingerprints())
          .containsExactly(
              SoftwareIdentity.newBuilder().setSoftware("test").build(),
              FingerprintData.fromProto(
                  Fingerprints.newBuilder()
                      .setSoftwareIdentity(SoftwareIdentity.newBuilder().setSoftware("test"))
                      .addContentHashes(
                          ContentHash.newBuilder()
                              .setContentPath("/test")
                              .addHashes(Hash.newBuilder().setHexString("123")))
                      .addContentHashes(
                          ContentHash.newBuilder()
                              .setContentPath("/test2")
                              .addHashes(Hash.newBuilder().setHexString("234")))
                      .addHashVersions(
                          HashVersion.newBuilder()
                              .setHash(Hash.newBuilder().setHexString("123"))
                              .addVersions(Version.newBuilder().setFullName("1.0"))
                              .addVersions(Version.newBuilder().setFullName("2.0")))
                      .addHashVersions(
                          HashVersion.newBuilder()
                              .setHash(Hash.newBuilder().setHexString("234"))
                              .addVersions(Version.newBuilder().setFullName("1.0"))
                              .addVersions(Version.newBuilder().setFullName("3.0")))
                      .addPathVersions(
                          PathVersion.newBuilder()
                              .setContentPath("/test")
                              .addVersions(Version.newBuilder().setFullName("1.0"))
                              .addVersions(Version.newBuilder().setFullName("2.0")))
                      .addPathVersions(
                          PathVersion.newBuilder()
                              .setContentPath("/test2")
                              .addVersions(Version.newBuilder().setFullName("1.0"))
                              .addVersions(Version.newBuilder().setFullName("3.0")))
                      .build()),
              SoftwareIdentity.newBuilder().setSoftware("test2").setPlugin("plugin").build(),
              FingerprintData.fromProto(
                  Fingerprints.newBuilder()
                      .setSoftwareIdentity(
                          SoftwareIdentity.newBuilder().setSoftware("test2").setPlugin("plugin"))
                      .addContentHashes(
                          ContentHash.newBuilder()
                              .setContentPath("/test")
                              .addHashes(Hash.newBuilder().setHexString("123")))
                      .addHashVersions(
                          HashVersion.newBuilder()
                              .setHash(Hash.newBuilder().setHexString("123"))
                              .addVersions(Version.newBuilder().setFullName("1.0"))
                              .addVersions(Version.newBuilder().setFullName("2.0")))
                      .addPathVersions(
                          PathVersion.newBuilder()
                              .setContentPath("/test")
                              .addVersions(Version.newBuilder().setFullName("1.0"))
                              .addVersions(Version.newBuilder().setFullName("2.0")))
                      .build()));
    }
  }
}
