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
package com.google.tsunami.plugins.fingerprinters.web.detection;

import static com.google.common.truth.Truth.assertThat;
import static com.google.tsunami.plugins.fingerprinters.web.CommonTestData.COMMON_LIB;
import static com.google.tsunami.plugins.fingerprinters.web.CommonTestData.FINGERPRINT_DATA_1;
import static com.google.tsunami.plugins.fingerprinters.web.CommonTestData.FINGERPRINT_DATA_2;
import static com.google.tsunami.plugins.fingerprinters.web.CommonTestData.SOFTWARE_1_CSS;
import static com.google.tsunami.plugins.fingerprinters.web.CommonTestData.SOFTWARE_1_CSS_HASH;
import static com.google.tsunami.plugins.fingerprinters.web.CommonTestData.SOFTWARE_1_ICON;
import static com.google.tsunami.plugins.fingerprinters.web.CommonTestData.SOFTWARE_1_ICON_HASH;
import static com.google.tsunami.plugins.fingerprinters.web.CommonTestData.SOFTWARE_1_JQUERY;
import static com.google.tsunami.plugins.fingerprinters.web.CommonTestData.SOFTWARE_2_CSS;
import static com.google.tsunami.plugins.fingerprinters.web.CommonTestData.SOFTWARE_2_ICON;
import static com.google.tsunami.plugins.fingerprinters.web.CommonTestData.SOFTWARE_2_ICON_HASH;
import static com.google.tsunami.plugins.fingerprinters.web.CommonTestData.SOFTWARE_2_JQUERY;
import static com.google.tsunami.plugins.fingerprinters.web.CommonTestData.SOFTWARE_IDENTITY_1;
import static com.google.tsunami.plugins.fingerprinters.web.CommonTestData.SOFTWARE_IDENTITY_2;
import static com.google.tsunami.plugins.fingerprinters.web.CommonTestData.UNKNOWN_CONTENT;
import static com.google.tsunami.plugins.fingerprinters.web.CommonTestData.fakeUrl;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.google.inject.AbstractModule;
import com.google.inject.Guice;
import com.google.inject.Provides;
import com.google.tsunami.plugins.fingerprinters.web.data.FingerprintData;
import com.google.tsunami.plugins.fingerprinters.web.detection.SoftwareDetector.DetectedSoftware;
import com.google.tsunami.plugins.fingerprinters.web.proto.SoftwareIdentity;
import com.google.tsunami.proto.CrawlResult;
import javax.inject.Inject;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for {@link SoftwareDetector}. */
@RunWith(JUnit4.class)
public final class SoftwareDetectorTest {

  @Inject SoftwareDetector softwareDetector;

  @Before
  public void setUp() {
    Guice.createInjector(
            new AbstractModule() {
              @Provides
              ImmutableMap<SoftwareIdentity, FingerprintData> provideFingerprints() {
                return ImmutableMap.of(
                    SOFTWARE_IDENTITY_1,
                    FINGERPRINT_DATA_1,
                    SOFTWARE_IDENTITY_2,
                    FINGERPRINT_DATA_2);
              }
            })
        .injectMembers(this);
  }

  @Test
  public void detectSoftware_whenOnlyOneSoftwareMatchOnRoot_returnsMatchedSoftware() {
    assertThat(softwareDetector.detectSoftware(ImmutableSet.of(SOFTWARE_1_ICON, UNKNOWN_CONTENT)))
        .containsExactly(
            DetectedSoftware.builder()
                .setSoftwareIdentity(SOFTWARE_IDENTITY_1)
                .setRootPath("/")
                .setContentHashes(ImmutableMap.of(SOFTWARE_1_ICON, SOFTWARE_1_ICON_HASH))
                .build());
  }

  @Test
  public void detectSoftware_whenOnlyOneSoftwareMatchOnSubFolder_returnsMatchedSoftware() {
    CrawlResult software1IconOnSubFolder =
        SOFTWARE_1_ICON.toBuilder()
            .setCrawlTarget(
                SOFTWARE_1_ICON.getCrawlTarget().toBuilder().setUrl(fakeUrl("/subfolder/icon.png")))
            .build();
    assertThat(
            softwareDetector.detectSoftware(
                ImmutableSet.of(software1IconOnSubFolder, UNKNOWN_CONTENT)))
        .containsExactly(
            DetectedSoftware.builder()
                .setSoftwareIdentity(SOFTWARE_IDENTITY_1)
                .setRootPath("/subfolder/")
                .setContentHashes(ImmutableMap.of(software1IconOnSubFolder, SOFTWARE_1_ICON_HASH))
                .build());
  }

  @Test
  public void detectSoftware_whenTwoSoftwareOnDifferentPaths_returnsAllMatchedSoftware() {
    CrawlResult software2IconOnSubFolder =
        SOFTWARE_2_ICON.toBuilder()
            .setCrawlTarget(
                SOFTWARE_2_ICON.getCrawlTarget().toBuilder().setUrl(fakeUrl("/subfolder/icon.png")))
            .build();
    assertThat(
            softwareDetector.detectSoftware(
                ImmutableSet.of(SOFTWARE_1_ICON, software2IconOnSubFolder, UNKNOWN_CONTENT)))
        .containsExactly(
            DetectedSoftware.builder()
                .setSoftwareIdentity(SOFTWARE_IDENTITY_1)
                .setRootPath("/")
                .setContentHashes(ImmutableMap.of(SOFTWARE_1_ICON, SOFTWARE_1_ICON_HASH))
                .build(),
            DetectedSoftware.builder()
                .setSoftwareIdentity(SOFTWARE_IDENTITY_2)
                .setRootPath("/subfolder/")
                .setContentHashes(ImmutableMap.of(software2IconOnSubFolder, SOFTWARE_2_ICON_HASH))
                .build());
  }

  @Test
  public void detectSoftware_whenCrawlResultsOnlyContainsCommonHashes_ignoresAllResults() {
    CrawlResult commonLibOnSubFolder =
        COMMON_LIB.toBuilder()
            .setCrawlTarget(
                COMMON_LIB.getCrawlTarget().toBuilder().setUrl(fakeUrl("/subfolder/common/lib.js")))
            .build();
    assertThat(softwareDetector.detectSoftware(ImmutableSet.of(commonLibOnSubFolder))).isEmpty();
  }

  @Test
  public void detectSoftware_whenCommonHashOnUnknownPath_returnsEmpty() {
    CrawlResult commonLibOnUnknownFolder =
        COMMON_LIB.toBuilder()
            .setCrawlTarget(
                COMMON_LIB.getCrawlTarget().toBuilder().setUrl(fakeUrl("/unknown/lib.js")))
            .build();
    assertThat(softwareDetector.detectSoftware(ImmutableSet.of(commonLibOnUnknownFolder)))
        .isEmpty();
  }

  @Test
  public void
      detectSoftware_whenGloballyUniqueHashOnUnknownPath_returnsMatchedSoftwareWithEmptyRoot() {
    CrawlResult software1IconOnUnknownPath =
        SOFTWARE_1_ICON.toBuilder()
            .setCrawlTarget(
                SOFTWARE_1_ICON.getCrawlTarget().toBuilder().setUrl(fakeUrl("/unknownIcon.png")))
            .build();
    assertThat(softwareDetector.detectSoftware(ImmutableSet.of(software1IconOnUnknownPath)))
        .containsExactly(
            DetectedSoftware.builder()
                .setSoftwareIdentity(SOFTWARE_IDENTITY_1)
                .setRootPath("")
                .setContentHashes(ImmutableMap.of(software1IconOnUnknownPath, SOFTWARE_1_ICON_HASH))
                .build());
  }

  @Test
  public void detectSoftware_whenMultiplePossibleFolders_returnsRootPathOnLongestCommonPrefix() {
    CrawlResult software1IconOnSubFolder =
        SOFTWARE_1_ICON.toBuilder()
            .setCrawlTarget(
                SOFTWARE_1_ICON.getCrawlTarget().toBuilder()
                    .setUrl(fakeUrl("/subfolder/sta1/icon.png")))
            .build();
    CrawlResult software1CssOnSubFolder =
        SOFTWARE_1_CSS.toBuilder()
            .setCrawlTarget(
                SOFTWARE_1_CSS.getCrawlTarget().toBuilder()
                    .setUrl(fakeUrl("/subfolder/sta2/software1/m.css")))
            .build();
    assertThat(
            softwareDetector.detectSoftware(
                ImmutableSet.of(software1IconOnSubFolder, software1CssOnSubFolder)))
        .containsExactly(
            DetectedSoftware.builder()
                .setSoftwareIdentity(SOFTWARE_IDENTITY_1)
                .setRootPath("/subfolder/")
                .setContentHashes(
                    ImmutableMap.of(
                        software1IconOnSubFolder,
                        SOFTWARE_1_ICON_HASH,
                        software1CssOnSubFolder,
                        SOFTWARE_1_CSS_HASH))
                .build());
  }

  @Test
  public void
      detectSoftware_whenCrawledUrlHasParamAndFragment_returnsRootPathIgnoringParamAndFragment() {
    CrawlResult software1IconOnSubFolder =
        SOFTWARE_1_ICON.toBuilder()
            .setCrawlTarget(
                SOFTWARE_1_ICON.getCrawlTarget().toBuilder()
                    .setUrl(fakeUrl("/subfolder/icon.png") + "?param=param_value#fragment"))
            .build();
    assertThat(
            softwareDetector.detectSoftware(
                ImmutableSet.of(software1IconOnSubFolder, UNKNOWN_CONTENT)))
        .containsExactly(
            DetectedSoftware.builder()
                .setSoftwareIdentity(SOFTWARE_IDENTITY_1)
                .setRootPath("/subfolder/")
                .setContentHashes(ImmutableMap.of(software1IconOnSubFolder, SOFTWARE_1_ICON_HASH))
                .build());
  }

  @Test
  public void detectSoftware_whenNoSoftwareMatch_returnsEmpty() {
    assertThat(softwareDetector.detectSoftware(ImmutableSet.of(UNKNOWN_CONTENT))).isEmpty();
  }

  @Test
  public void detectSoftware_whenNoFingerprintData_returnsEmpty() {
    softwareDetector =
        Guice.createInjector(
                new AbstractModule() {
                  @Provides
                  ImmutableMap<SoftwareIdentity, FingerprintData> provideFingerprints() {
                    return ImmutableMap.of();
                  }
                })
            .getInstance(SoftwareDetector.class);
    assertThat(
            softwareDetector.detectSoftware(
                ImmutableSet.of(
                    COMMON_LIB,
                    SOFTWARE_1_JQUERY,
                    SOFTWARE_1_CSS,
                    SOFTWARE_1_ICON,
                    SOFTWARE_2_JQUERY,
                    SOFTWARE_2_CSS,
                    SOFTWARE_2_ICON)))
        .isEmpty();
  }
}
