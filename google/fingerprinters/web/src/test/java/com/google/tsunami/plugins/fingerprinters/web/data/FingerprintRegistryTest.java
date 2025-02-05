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
import static com.google.common.truth.extensions.proto.ProtoTruth.assertThat;

import com.google.common.collect.ImmutableMap;
import com.google.inject.AbstractModule;
import com.google.inject.Guice;
import com.google.inject.Provides;
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
import javax.inject.Inject;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for {@link FingerprintRegistry}. */
@RunWith(JUnit4.class)
public final class FingerprintRegistryTest {
  private static final Fingerprints FINGERPRINTS_1 =
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
          .build();
  private static final Fingerprints FINGERPRINTS_2 =
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
          .build();

  @Inject FingerprintRegistry registry;

  @Before
  public void setUp() {
    try (ScanResult scanResult =
        new ClassGraph()
            .enableAllInfo()
            .whitelistPaths("com/google/tsunami/plugins/fingerprinters/web/data/testdata")
            .scan()) {
      Guice.createInjector(
              new AbstractModule() {
                @Provides
                ImmutableMap<SoftwareIdentity, FingerprintData> provideFingerprints()
                    throws IOException {
                  return new ResourceFingerprintLoader(scanResult).loadFingerprints();
                }
              })
          .injectMembers(this);
    }
  }

  @Test
  public void allSoftware_whenEmptyFingerprintData_returnsEmptySet() {
    assertThat(new FingerprintRegistry(ImmutableMap.of()).allSoftware()).isEmpty();
  }

  @Test
  public void allSoftware_whenValidFingerprintData_returnsAllSoftware() {
    assertThat(registry.allSoftware())
        .containsExactly(
            FINGERPRINTS_1.getSoftwareIdentity(), FINGERPRINTS_2.getSoftwareIdentity());
  }

  @Test
  public void matchSoftwareForHash_whenEmptyFingerprintData_returnsEmptySet() {
    FingerprintRegistry registry = new FingerprintRegistry(ImmutableMap.of());

    assertThat(registry.matchSoftwareForHash(Hash.getDefaultInstance())).isEmpty();
    assertThat(registry.matchSoftwareForHash(Hash.newBuilder().setHexString("whatever").build()))
        .isEmpty();
  }

  @Test
  public void
  matchSoftwareForHash_whenValidFingerprintDataAndMultipleMatch_returnsMatchedSoftware() {
    assertThat(registry.matchSoftwareForHash(Hash.newBuilder().setHexString("123").build()))
        .containsExactly(
            FINGERPRINTS_1.getSoftwareIdentity(), FINGERPRINTS_2.getSoftwareIdentity());
  }

  @Test
  public void matchSoftwareForHash_whenValidFingerprintDataAndSingleMatch_returnsMatchedSoftware() {
    assertThat(registry.matchSoftwareForHash(Hash.newBuilder().setHexString("234").build()))
        .containsExactly(FINGERPRINTS_1.getSoftwareIdentity());
  }

  @Test
  public void getFingerprints_whenEmptyFingerprintData_returnsEmpty() {
    assertThat(
            new FingerprintRegistry(ImmutableMap.of())
                .getFingerprintData(SoftwareIdentity.getDefaultInstance()))
        .isEmpty();
    assertThat(
            new FingerprintRegistry(ImmutableMap.of())
                .getFingerprintData(SoftwareIdentity.newBuilder().setSoftware("whatever").build()))
        .isEmpty();
  }

  @Test
  public void getFingerprints_whenValidFingerprintDataAndNoMatchingSoftware_returnsEmpty() {
    assertThat(registry.getFingerprintData(SoftwareIdentity.getDefaultInstance())).isEmpty();
  }

  @Test
  public void getFingerprints_whenValidFingerprintDataAndMatchingSoftware_returnsFingerprint() {
    assertThat(registry.getFingerprintData(FINGERPRINTS_1.getSoftwareIdentity()))
        .hasValue(FingerprintData.fromProto(FINGERPRINTS_1));
    assertThat(registry.getFingerprintData(FINGERPRINTS_2.getSoftwareIdentity()))
        .hasValue(FingerprintData.fromProto(FINGERPRINTS_2));
  }

  @Test
  public void isGloballyUniqueHash_whenNotUnique_returnsFalse() {
    assertThat(registry.isGloballyUniqueHash(Hash.newBuilder().setHexString("123").build()))
        .isFalse();
  }

  @Test
  public void isGloballyUniqueHash_whenTruelyUnique_returnsTrue() {
    assertThat(registry.isGloballyUniqueHash(Hash.newBuilder().setHexString("234").build()))
        .isTrue();
  }

  @Test
  public void isGloballyUniqueHash_whenUnknownHash_returnsTrue() {
    assertThat(registry.isGloballyUniqueHash(Hash.newBuilder().setHexString("abc").build()))
        .isTrue();
  }

  @Test
  public void isGloballyUniquePath_whenNotUnique_returnsFalse() {
    assertThat(registry.isGloballyUniquePath("/test")).isFalse();
  }

  @Test
  public void isGloballyUniquePath_whenTruelyUnique_returnsTrue() {
    assertThat(registry.isGloballyUniquePath("/test2")).isTrue();
  }

  @Test
  public void isGloballyUniquePath_whenUnknownPath_returnsTrue() {
    assertThat(registry.isGloballyUniquePath("/unknown")).isTrue();
  }
}
