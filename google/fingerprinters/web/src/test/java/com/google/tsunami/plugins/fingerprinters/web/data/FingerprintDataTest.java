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

import static com.google.common.truth.extensions.proto.ProtoTruth.assertThat;

import com.google.common.io.Resources;
import com.google.tsunami.plugins.fingerprinters.web.proto.ContentHash;
import com.google.tsunami.plugins.fingerprinters.web.proto.Fingerprints;
import com.google.tsunami.plugins.fingerprinters.web.proto.Hash;
import com.google.tsunami.plugins.fingerprinters.web.proto.HashVersion;
import com.google.tsunami.plugins.fingerprinters.web.proto.PathVersion;
import com.google.tsunami.plugins.fingerprinters.web.proto.SoftwareIdentity;
import com.google.tsunami.plugins.fingerprinters.web.proto.Version;
import java.io.IOException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for {@link FingerprintData}. */
@RunWith(JUnit4.class)
public final class FingerprintDataTest {

  private static final Hash HASH_1 = Hash.newBuilder().setHexString("123").build();
  private static final Hash HASH_2 = Hash.newBuilder().setHexString("234").build();
  private static final Version VERSION_1 = Version.newBuilder().setFullName("1.0").build();
  private static final Version VERSION_2 = Version.newBuilder().setFullName("2.0").build();
  private static final Version VERSION_3 = Version.newBuilder().setFullName("3.0").build();

  @Test
  public void fromProto_always_generatesFingerprintDataFromProtoMessage() throws IOException {
    FingerprintData fingerprintData =
        FingerprintData.fromProto(
            Fingerprints.parseFrom(
                Resources.toByteArray(
                    Resources.getResource(this.getClass(), "testdata/test.binproto"))));
    assertThat(fingerprintData.softwareIdentity())
        .isEqualTo(SoftwareIdentity.newBuilder().setSoftware("test").build());
    assertThat(fingerprintData.contentHashes())
        .containsExactly(
            "/test",
            ContentHash.newBuilder().setContentPath("/test").addHashes(HASH_1).build(),
            "/test2",
            ContentHash.newBuilder().setContentPath("/test2").addHashes(HASH_2).build());
    assertThat(fingerprintData.hashVersions())
        .containsExactly(
            HASH_1,
            HashVersion.newBuilder()
                .setHash(HASH_1)
                .addVersions(VERSION_1)
                .addVersions(VERSION_2)
                .build(),
            HASH_2,
            HashVersion.newBuilder()
                .setHash(HASH_2)
                .addVersions(VERSION_1)
                .addVersions(VERSION_3)
                .build());
    assertThat(fingerprintData.pathVersions())
        .containsExactly(
            "/test",
            PathVersion.newBuilder()
                .setContentPath("/test")
                .addVersions(VERSION_1)
                .addVersions(VERSION_2)
                .build(),
            "/test2",
            PathVersion.newBuilder()
                .setContentPath("/test2")
                .addVersions(VERSION_1)
                .addVersions(VERSION_3)
                .build());
  }
}
