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
import static com.google.tsunami.plugins.fingerprinters.web.CommonTestData.COMMON_LIB_HASH;
import static com.google.tsunami.plugins.fingerprinters.web.CommonTestData.FINGERPRINT_DATA_1;
import static com.google.tsunami.plugins.fingerprinters.web.CommonTestData.FINGERPRINT_DATA_2;
import static com.google.tsunami.plugins.fingerprinters.web.CommonTestData.SOFTWARE_1_CSS;
import static com.google.tsunami.plugins.fingerprinters.web.CommonTestData.SOFTWARE_1_CSS_HASH;
import static com.google.tsunami.plugins.fingerprinters.web.CommonTestData.SOFTWARE_1_ICON;
import static com.google.tsunami.plugins.fingerprinters.web.CommonTestData.SOFTWARE_1_ICON_HASH;
import static com.google.tsunami.plugins.fingerprinters.web.CommonTestData.SOFTWARE_2_CSS_HASH;
import static com.google.tsunami.plugins.fingerprinters.web.CommonTestData.SOFTWARE_2_CSS_NEW_PATH;
import static com.google.tsunami.plugins.fingerprinters.web.CommonTestData.SOFTWARE_2_CSS_UNKNOWN_VERSION_PATH;
import static com.google.tsunami.plugins.fingerprinters.web.CommonTestData.SOFTWARE_2_ICON;
import static com.google.tsunami.plugins.fingerprinters.web.CommonTestData.SOFTWARE_2_ICON_HASH;
import static com.google.tsunami.plugins.fingerprinters.web.CommonTestData.SOFTWARE_IDENTITY_1;
import static com.google.tsunami.plugins.fingerprinters.web.CommonTestData.SOFTWARE_IDENTITY_2;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.inject.AbstractModule;
import com.google.inject.Guice;
import com.google.inject.Provides;
import com.google.inject.assistedinject.FactoryModuleBuilder;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.common.net.http.HttpStatus;
import com.google.tsunami.plugins.fingerprinters.web.data.FingerprintData;
import com.google.tsunami.plugins.fingerprinters.web.detection.SoftwareDetector.DetectedSoftware;
import com.google.tsunami.plugins.fingerprinters.web.detection.VersionDetector.DetectedVersion;
import com.google.tsunami.plugins.fingerprinters.web.proto.SoftwareIdentity;
import com.google.tsunami.plugins.fingerprinters.web.proto.Version;
import com.google.tsunami.proto.CrawlResult;
import com.google.tsunami.proto.NetworkService;
import java.io.IOException;
import javax.inject.Inject;
import okhttp3.HttpUrl;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for {@link VersionDetector}. */
@RunWith(JUnit4.class)
public final class VersionDetectorTest {
  private static final int ALLOWED_FAILED_REQUEST = 1;
  private static final int ALLOWED_HTTP_REQUEST = 10;

  private MockWebServer mockWebServer;
  private NetworkService fakeNetworkService;
  @Inject VersionDetector.Factory versionDetectorFactory;

  @Before
  public void setUp() {
    mockWebServer = new MockWebServer();
    fakeNetworkService = NetworkService.getDefaultInstance();
    Guice.createInjector(
            new AbstractModule() {
              @Override
              protected void configure() {
                install(new HttpClientModule.Builder().build());
                install(new FactoryModuleBuilder().build(VersionDetector.Factory.class));
              }

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

  @After
  public void tearDown() throws IOException {
    mockWebServer.shutdown();
  }

  @Test
  public void detectVersions_whenHashOnlySeenInOneVersion_returnsOneMatchingVersion() {
    DetectedSoftware detectedSoftware =
        DetectedSoftware.builder()
            .setSoftwareIdentity(SOFTWARE_IDENTITY_1)
            .setRootPath("")
            .setContentHashes(
                ImmutableMap.of(
                    updateUrl(COMMON_LIB),
                    COMMON_LIB_HASH,
                    updateUrl(SOFTWARE_1_ICON),
                    SOFTWARE_1_ICON_HASH))
            .build();
    assertThat(
            versionDetectorFactory
                .create(
                    fakeNetworkService,
                    FINGERPRINT_DATA_1,
                    detectedSoftware,
                    ALLOWED_FAILED_REQUEST,
                    ALLOWED_HTTP_REQUEST)
                .detectVersions())
        .isEqualTo(
            DetectedVersion.builder()
                .setSoftwareIdentity(SOFTWARE_IDENTITY_1)
                .setVersions(ImmutableList.of(Version.newBuilder().setFullName("1.0").build()))
                .build());
    assertThat(mockWebServer.getRequestCount()).isEqualTo(0);
  }

  @Test
  public void detectVersions_whenHashInMultipleVersionsNoSucceededRequests_returnsMultipleVersions()
      throws InterruptedException {
    DetectedSoftware detectedSoftware =
        DetectedSoftware.builder()
            .setSoftwareIdentity(SOFTWARE_IDENTITY_1)
            .setRootPath("")
            .setContentHashes(
                ImmutableMap.of(
                    updateUrl(COMMON_LIB),
                    COMMON_LIB_HASH,
                    updateUrl(SOFTWARE_1_CSS),
                    SOFTWARE_1_CSS_HASH))
            .build();
    assertThat(
            versionDetectorFactory
                .create(
                    fakeNetworkService,
                    FINGERPRINT_DATA_1,
                    detectedSoftware,
                    ALLOWED_FAILED_REQUEST,
                    ALLOWED_HTTP_REQUEST)
                .detectVersions())
        .isEqualTo(
            DetectedVersion.builder()
                .setSoftwareIdentity(SOFTWARE_IDENTITY_1)
                .setVersions(
                    ImmutableList.of(
                        Version.newBuilder().setFullName("1.2").build(),
                        Version.newBuilder().setFullName("1.3").build()))
                .build());
    assertThat(mockWebServer.getRequestCount()).isEqualTo(1);
    assertThat(mockWebServer.takeRequest().getPath()).isEqualTo("/software1/jquery.js");
  }

  @Test
  public void
      detectVersions_whenHashInMultipleVersionsUnstableFilesNarrowDownVersion_returnsSingleVersion()
          throws InterruptedException, IOException {
    mockWebServer.enqueue(
        new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody("common jquery"));
    mockWebServer.start();
    DetectedSoftware detectedSoftware =
        DetectedSoftware.builder()
            .setSoftwareIdentity(SOFTWARE_IDENTITY_1)
            .setRootPath("")
            .setContentHashes(
                ImmutableMap.of(
                    updateUrl(COMMON_LIB),
                    COMMON_LIB_HASH,
                    updateUrl(SOFTWARE_1_CSS),
                    SOFTWARE_1_CSS_HASH))
            .build();
    assertThat(
            versionDetectorFactory
                .create(
                    fakeNetworkService,
                    FINGERPRINT_DATA_1,
                    detectedSoftware,
                    ALLOWED_FAILED_REQUEST,
                    ALLOWED_HTTP_REQUEST)
                .detectVersions())
        .isEqualTo(
            DetectedVersion.builder()
                .setSoftwareIdentity(SOFTWARE_IDENTITY_1)
                .setVersions(ImmutableList.of(Version.newBuilder().setFullName("1.2").build()))
                .build());
    assertThat(mockWebServer.getRequestCount()).isEqualTo(1);
    assertThat(mockWebServer.takeRequest().getPath()).isEqualTo("/software1/jquery.js");
  }

  @Test
  public void detectVersions_whenHashInMultipleVersionsButPathInSingleVersion_returnsSingleVersion()
      throws InterruptedException {
    DetectedSoftware detectedSoftware =
        DetectedSoftware.builder()
            .setSoftwareIdentity(SOFTWARE_IDENTITY_2)
            .setRootPath("")
            .setContentHashes(
                ImmutableMap.of(
                    updateUrl(COMMON_LIB),
                    COMMON_LIB_HASH,
                    updateUrl(SOFTWARE_2_CSS_NEW_PATH),
                    SOFTWARE_2_CSS_HASH))
            .build();
    assertThat(
            versionDetectorFactory
                .create(
                    fakeNetworkService,
                    FINGERPRINT_DATA_2,
                    detectedSoftware,
                    ALLOWED_FAILED_REQUEST,
                    ALLOWED_HTTP_REQUEST)
                .detectVersions())
        .isEqualTo(
            DetectedVersion.builder()
                .setSoftwareIdentity(SOFTWARE_IDENTITY_2)
                .setVersions(ImmutableList.of(Version.newBuilder().setFullName("2.1").build()))
                .build());
  }

  @Test
  public void detectVersions_whenPathNotInPathVersions_ignorePathVersions()
      throws InterruptedException {
    DetectedSoftware detectedSoftware =
        DetectedSoftware.builder()
            .setSoftwareIdentity(SOFTWARE_IDENTITY_2)
            .setRootPath("")
            .setContentHashes(
                ImmutableMap.of(
                    updateUrl(SOFTWARE_2_CSS_UNKNOWN_VERSION_PATH), SOFTWARE_2_CSS_HASH))
            .build();
    assertThat(
            versionDetectorFactory
                .create(
                    fakeNetworkService,
                    FINGERPRINT_DATA_2,
                    detectedSoftware,
                    ALLOWED_FAILED_REQUEST,
                    ALLOWED_HTTP_REQUEST)
                .detectVersions())
        .isEqualTo(
            DetectedVersion.builder()
                .setSoftwareIdentity(SOFTWARE_IDENTITY_2)
                .setVersions(
                    ImmutableList.of(
                        Version.newBuilder().setFullName("2.0").build(),
                        Version.newBuilder().setFullName("2.1").build()))
                .build());
  }

  @Test
  public void detectVersions_whenValidRootPathAndMakingAdditionalRequest_queriesFileUnderRootPath()
      throws InterruptedException, IOException {
    mockWebServer.enqueue(
        new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody("common jquery"));
    mockWebServer.start();
    DetectedSoftware detectedSoftware =
        DetectedSoftware.builder()
            .setSoftwareIdentity(SOFTWARE_IDENTITY_1)
            .setRootPath("/root/path")
            .setContentHashes(
                ImmutableMap.of(
                    updateUrl(COMMON_LIB),
                    COMMON_LIB_HASH,
                    updateUrl(SOFTWARE_1_CSS),
                    SOFTWARE_1_CSS_HASH))
            .build();
    assertThat(
            versionDetectorFactory
                .create(
                    fakeNetworkService,
                    FINGERPRINT_DATA_1,
                    detectedSoftware,
                    ALLOWED_FAILED_REQUEST,
                    ALLOWED_HTTP_REQUEST)
                .detectVersions())
        .isEqualTo(
            DetectedVersion.builder()
                .setSoftwareIdentity(SOFTWARE_IDENTITY_1)
                .setVersions(ImmutableList.of(Version.newBuilder().setFullName("1.2").build()))
                .build());
    assertThat(mockWebServer.getRequestCount()).isEqualTo(1);
    assertThat(mockWebServer.takeRequest().getPath()).isEqualTo("/root/path/software1/jquery.js");
  }

  @Test
  public void detectVersions_whenAdditionalRequestsExceedsLimit_stopsSendingRequests()
      throws InterruptedException, IOException {
    mockWebServer.enqueue(
        new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody("common jquery"));
    mockWebServer.start();
    DetectedSoftware detectedSoftware =
        DetectedSoftware.builder()
            .setSoftwareIdentity(SOFTWARE_IDENTITY_1)
            .setRootPath("")
            .setContentHashes(
                ImmutableMap.of(
                    updateUrl(COMMON_LIB),
                    COMMON_LIB_HASH,
                    updateUrl(SOFTWARE_1_CSS),
                    SOFTWARE_1_CSS_HASH))
            .build();
    assertThat(
            versionDetectorFactory
                .create(
                    fakeNetworkService,
                    FINGERPRINT_DATA_1,
                    detectedSoftware,
                    ALLOWED_FAILED_REQUEST,
                    // Set maxAllowedHttpRequest to 0 to disable additional requests.
                    /*maxAllowedHttpRequest=*/ 0)
                .detectVersions())
        .isEqualTo(
            DetectedVersion.builder()
                .setSoftwareIdentity(SOFTWARE_IDENTITY_1)
                .setVersions(
                    ImmutableList.of(
                        Version.newBuilder().setFullName("1.2").build(),
                        Version.newBuilder().setFullName("1.3").build()))
                .build());
    assertThat(mockWebServer.getRequestCount()).isEqualTo(0);
  }

  @Test
  public void detectVersions_whenHashInMultipleVersionsNoAdditionalFiles_returnsMultipleVersions() {
    DetectedSoftware detectedSoftware =
        DetectedSoftware.builder()
            .setSoftwareIdentity(SOFTWARE_IDENTITY_2)
            .setRootPath("")
            .setContentHashes(
                ImmutableMap.of(
                    updateUrl(COMMON_LIB),
                    COMMON_LIB_HASH,
                    updateUrl(SOFTWARE_2_ICON),
                    SOFTWARE_2_ICON_HASH))
            .build();
    assertThat(
            versionDetectorFactory
                .create(
                    fakeNetworkService,
                    FINGERPRINT_DATA_2,
                    detectedSoftware,
                    ALLOWED_FAILED_REQUEST,
                    ALLOWED_HTTP_REQUEST)
                .detectVersions())
        .isEqualTo(
            DetectedVersion.builder()
                .setSoftwareIdentity(SOFTWARE_IDENTITY_2)
                .setVersions(
                    ImmutableList.of(
                        Version.newBuilder().setFullName("2.0").build(),
                        Version.newBuilder().setFullName("2.1").build()))
                .build());
    assertThat(mockWebServer.getRequestCount()).isEqualTo(0);
  }

  @Test
  public void detectVersions_whenUnstableFilesDoesNotNarrowDownVersion_skipsUnstableFiles() {
    DetectedSoftware detectedSoftware =
        DetectedSoftware.builder()
            .setSoftwareIdentity(SOFTWARE_IDENTITY_2)
            .setRootPath("")
            .setContentHashes(ImmutableMap.of(updateUrl(SOFTWARE_2_ICON), SOFTWARE_2_ICON_HASH))
            .build();
    assertThat(
            versionDetectorFactory
                .create(
                    fakeNetworkService,
                    FINGERPRINT_DATA_2,
                    detectedSoftware,
                    ALLOWED_FAILED_REQUEST,
                    ALLOWED_HTTP_REQUEST)
                .detectVersions())
        .isEqualTo(
            DetectedVersion.builder()
                .setSoftwareIdentity(SOFTWARE_IDENTITY_2)
                .setVersions(
                    ImmutableList.of(
                        Version.newBuilder().setFullName("2.0").build(),
                        Version.newBuilder().setFullName("2.1").build()))
                .build());
    assertThat(mockWebServer.getRequestCount()).isEqualTo(0);
  }

  @Test
  public void detectVersions_whenPotentialVersionsNoIntersection_returnsNoMatchingVersions() {
    DetectedSoftware detectedSoftware =
        DetectedSoftware.builder()
            .setSoftwareIdentity(SOFTWARE_IDENTITY_1)
            .setRootPath("")
            .setContentHashes(
                ImmutableMap.of(
                    updateUrl(SOFTWARE_1_CSS),
                    SOFTWARE_1_CSS_HASH,
                    updateUrl(SOFTWARE_1_ICON),
                    SOFTWARE_1_ICON_HASH))
            .build();
    assertThat(
            versionDetectorFactory
                .create(
                    fakeNetworkService,
                    FINGERPRINT_DATA_1,
                    detectedSoftware,
                    ALLOWED_FAILED_REQUEST,
                    ALLOWED_HTTP_REQUEST)
                .detectVersions())
        .isEqualTo(
            DetectedVersion.builder()
                .setSoftwareIdentity(SOFTWARE_IDENTITY_1)
                .setVersions(ImmutableList.of())
                .build());
  }

  @Test
  public void detectVersions_whenNoContentHashes_returnsNoMatchingVersions() {
    DetectedSoftware detectedSoftware =
        DetectedSoftware.builder()
            .setSoftwareIdentity(SOFTWARE_IDENTITY_1)
            .setRootPath("")
            .setContentHashes(ImmutableMap.of())
            .build();
    assertThat(
            versionDetectorFactory
                .create(
                    fakeNetworkService,
                    FINGERPRINT_DATA_1,
                    detectedSoftware,
                    ALLOWED_FAILED_REQUEST,
                    ALLOWED_HTTP_REQUEST)
                .detectVersions())
        .isEqualTo(
            DetectedVersion.builder()
                .setSoftwareIdentity(SOFTWARE_IDENTITY_1)
                .setVersions(ImmutableList.of())
                .build());
  }

  private CrawlResult updateUrl(CrawlResult crawlResult) {
    String oldPath = HttpUrl.parse(crawlResult.getCrawlTarget().getUrl()).encodedPath();
    CrawlResult.Builder updatedCrawlResultBuilder = crawlResult.toBuilder();
    updatedCrawlResultBuilder.getCrawlTargetBuilder().setUrl(mockWebServer.url(oldPath).toString());
    return updatedCrawlResultBuilder.build();
  }
}
