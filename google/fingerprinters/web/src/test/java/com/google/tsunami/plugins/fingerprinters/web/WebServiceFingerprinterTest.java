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
package com.google.tsunami.plugins.fingerprinters.web;

import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.common.truth.extensions.proto.ProtoTruth.assertThat;
import static com.google.common.util.concurrent.Futures.immediateFuture;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostname;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forIp;
import static com.google.tsunami.plugins.fingerprinters.web.CommonTestData.COMMON_LIB;
import static com.google.tsunami.plugins.fingerprinters.web.CommonTestData.FINGERPRINT_DATA_1;
import static com.google.tsunami.plugins.fingerprinters.web.CommonTestData.FINGERPRINT_DATA_2;
import static com.google.tsunami.plugins.fingerprinters.web.CommonTestData.SOFTWARE_1_ICON;
import static com.google.tsunami.plugins.fingerprinters.web.CommonTestData.SOFTWARE_1_JQUERY;
import static com.google.tsunami.plugins.fingerprinters.web.CommonTestData.SOFTWARE_2_ICON;
import static com.google.tsunami.plugins.fingerprinters.web.CommonTestData.SOFTWARE_IDENTITY_1;
import static com.google.tsunami.plugins.fingerprinters.web.CommonTestData.SOFTWARE_IDENTITY_2;
import static com.google.tsunami.plugins.fingerprinters.web.CommonTestData.fakeUrl;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.google.common.util.concurrent.ListenableFuture;
import com.google.inject.AbstractModule;
import com.google.inject.Guice;
import com.google.inject.Provides;
import com.google.inject.assistedinject.FactoryModuleBuilder;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.plugins.fingerprinters.web.crawl.Crawler;
import com.google.tsunami.plugins.fingerprinters.web.data.FingerprintData;
import com.google.tsunami.plugins.fingerprinters.web.detection.VersionDetector;
import com.google.tsunami.plugins.fingerprinters.web.proto.SoftwareIdentity;
import com.google.tsunami.proto.CrawlConfig;
import com.google.tsunami.proto.CrawlResult;
import com.google.tsunami.proto.FingerprintingReport;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.ServiceContext;
import com.google.tsunami.proto.Software;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.Version;
import com.google.tsunami.proto.Version.VersionType;
import com.google.tsunami.proto.VersionSet;
import com.google.tsunami.proto.WebServiceContext;
import java.util.Collection;
import javax.inject.Inject;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for {@link WebServiceFingerprinter}. */
@RunWith(JUnit4.class)
public final class WebServiceFingerprinterTest {

  private final FakeCrawler fakeCrawler = new FakeCrawler();
  @Inject WebServiceFingerprinter fingerprinter;

  @Before
  public void setUp() {
    Guice.createInjector(
            new AbstractModule() {
              @Override
              protected void configure() {
                bind(Crawler.class).toInstance(fakeCrawler);
                install(new FactoryModuleBuilder().build(VersionDetector.Factory.class));
                install(new HttpClientModule.Builder().build());
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

  @Test
  public void
      fingerprint_whenCrawlResultsForSingleApplication_fillsServiceContextWithApplication() {
    fakeCrawler.setCrawlResults(ImmutableSet.of(COMMON_LIB, SOFTWARE_1_JQUERY, SOFTWARE_1_ICON));
    NetworkService networkService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(forHostname("localhost"))
            .setServiceName("http")
            .build();

    FingerprintingReport fingerprintingReport =
        fingerprinter.fingerprint(TargetInfo.getDefaultInstance(), networkService);

    assertThat(fingerprintingReport)
        .comparingExpectedFieldsOnly()
        .isEqualTo(
            FingerprintingReport.newBuilder()
                .addNetworkServices(
                    addServiceContext(
                        networkService,
                        "/",
                        SOFTWARE_IDENTITY_1.getSoftware(),
                        ImmutableList.of("1.0")))
                .build());
  }

  @Test
  public void fingerprint_whenApplicationServingUnderSubPath_fillsServiceContextWithSubpath() {
    fakeCrawler.setCrawlResults(
        ImmutableSet.of(
            SOFTWARE_1_JQUERY.toBuilder()
                .setCrawlTarget(
                    SOFTWARE_1_JQUERY.getCrawlTarget().toBuilder()
                        .setUrl(fakeUrl("/subfolder/software1/jquery.js")))
                .build(),
            SOFTWARE_1_ICON.toBuilder()
                .setCrawlTarget(
                    SOFTWARE_1_ICON.getCrawlTarget().toBuilder()
                        .setUrl(fakeUrl("/subfolder/icon.png")))
                .build()));
    NetworkService networkService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(forHostname("localhost"))
            .setServiceName("http")
            .build();

    FingerprintingReport fingerprintingReport =
        fingerprinter.fingerprint(TargetInfo.getDefaultInstance(), networkService);

    assertThat(fingerprintingReport)
        .comparingExpectedFieldsOnly()
        .isEqualTo(
            FingerprintingReport.newBuilder()
                .addNetworkServices(
                    addServiceContext(
                        networkService,
                        "/subfolder/",
                        SOFTWARE_IDENTITY_1.getSoftware(),
                        ImmutableList.of("1.0")))
                .build());
  }

  @Test
  public void
      fingerprint_whenCrawlResultsForMultipleApplication_fillsServiceContextWithAllApplications() {
    fakeCrawler.setCrawlResults(ImmutableSet.of(COMMON_LIB, SOFTWARE_1_ICON, SOFTWARE_2_ICON));
    NetworkService networkService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(forHostname("localhost"))
            .setServiceName("http")
            .build();

    FingerprintingReport fingerprintingReport =
        fingerprinter.fingerprint(TargetInfo.getDefaultInstance(), networkService);

    assertThat(fingerprintingReport)
        .ignoringRepeatedFieldOrder()
        .comparingExpectedFieldsOnly()
        .isEqualTo(
            FingerprintingReport.newBuilder()
                .addNetworkServices(
                    addServiceContext(
                        networkService,
                        "/",
                        SOFTWARE_IDENTITY_1.getSoftware(),
                        ImmutableList.of("1.0")))
                .addNetworkServices(
                    addServiceContext(
                        networkService,
                        "/",
                        SOFTWARE_IDENTITY_2.getSoftware(),
                        ImmutableList.of("2.0", "2.1")))
                .build());
  }

  @Test
  public void fingerprint_whenEmptyCrawlResult_skipsWebFingerprinting() {
    fakeCrawler.setCrawlResults(ImmutableSet.of());
    NetworkService networkService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(forIp("127.0.0.1"))
            .setServiceName("http")
            .setServiceContext(
                ServiceContext.newBuilder()
                    .setWebServiceContext(WebServiceContext.getDefaultInstance())
                    .build())
            .build();

    FingerprintingReport fingerprintingReport =
        fingerprinter.fingerprint(TargetInfo.getDefaultInstance(), networkService);

    assertThat(fingerprintingReport)
        .isEqualTo(FingerprintingReport.newBuilder().addNetworkServices(networkService).build());
  }
  // TODO(b/210549664): add tests for crawl results.

  private static NetworkService addServiceContext(
      NetworkService networkService, String appRoot, String appName, Collection<String> versions) {
    VersionSet versionSet =
        VersionSet.newBuilder()
            .addAllVersions(
                versions.stream()
                    .map(
                        version ->
                            Version.newBuilder()
                                .setType(VersionType.NORMAL)
                                .setFullVersionString(version)
                                .build())
                    .collect(toImmutableList()))
            .build();
    return networkService.toBuilder()
        .setServiceContext(
            ServiceContext.newBuilder()
                .setWebServiceContext(
                    WebServiceContext.newBuilder()
                        .setApplicationRoot(appRoot)
                        .setSoftware(Software.newBuilder().setName(appName))
                        .setVersionSet(versionSet)))
        .build();
  }

  private static final class FakeCrawler implements Crawler {
    private ImmutableSet<CrawlResult> crawlResults;

    public void setCrawlResults(ImmutableSet<CrawlResult> crawlResults) {
      this.crawlResults = crawlResults;
    }

    @Override
    public ListenableFuture<ImmutableSet<CrawlResult>> crawlAsync(CrawlConfig crawlConfig) {
      return immediateFuture(crawlResults);
    }
  }
}
