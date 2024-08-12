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
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostnameAndPort;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forIp;
import static com.google.tsunami.plugins.fingerprinters.web.CommonTestData.COMMON_LIB;
import static com.google.tsunami.plugins.fingerprinters.web.CommonTestData.FINGERPRINT_DATA_1;
import static com.google.tsunami.plugins.fingerprinters.web.CommonTestData.FINGERPRINT_DATA_2;
import static com.google.tsunami.plugins.fingerprinters.web.CommonTestData.FINGERPRINT_DATA_3;
import static com.google.tsunami.plugins.fingerprinters.web.CommonTestData.SOFTWARE_1_ICON;
import static com.google.tsunami.plugins.fingerprinters.web.CommonTestData.SOFTWARE_1_JQUERY;
import static com.google.tsunami.plugins.fingerprinters.web.CommonTestData.SOFTWARE_2_ICON;
import static com.google.tsunami.plugins.fingerprinters.web.CommonTestData.SOFTWARE_3_CSS;
import static com.google.tsunami.plugins.fingerprinters.web.CommonTestData.SOFTWARE_3_ZIP;
import static com.google.tsunami.plugins.fingerprinters.web.CommonTestData.SOFTWARE_4_MLFLOW;
import static com.google.tsunami.plugins.fingerprinters.web.CommonTestData.SOFTWARE_IDENTITY_1;
import static com.google.tsunami.plugins.fingerprinters.web.CommonTestData.SOFTWARE_IDENTITY_2;
import static com.google.tsunami.plugins.fingerprinters.web.CommonTestData.SOFTWARE_IDENTITY_3;
import static com.google.tsunami.plugins.fingerprinters.web.CommonTestData.SOFTWARE_IDENTITY_4;
import static com.google.tsunami.plugins.fingerprinters.web.CommonTestData.fakeUrl;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.google.common.util.concurrent.ListenableFuture;
import com.google.inject.AbstractModule;
import com.google.inject.Guice;
import com.google.inject.Provides;
import com.google.inject.assistedinject.FactoryModuleBuilder;
import com.google.tsunami.common.data.NetworkEndpointUtils;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.plugins.fingerprinters.web.WebServiceFingerprinterConfigs.WebServiceFingerprinterCliOptions;
import com.google.tsunami.plugins.fingerprinters.web.crawl.Crawler;
import com.google.tsunami.plugins.fingerprinters.web.data.FingerprintData;
import com.google.tsunami.plugins.fingerprinters.web.detection.VersionDetector;
import com.google.tsunami.plugins.fingerprinters.web.proto.SoftwareIdentity;
import com.google.tsunami.proto.CrawlConfig;
import com.google.tsunami.proto.CrawlResult;
import com.google.tsunami.proto.CrawlTarget;
import com.google.tsunami.proto.FingerprintingReport;
import com.google.tsunami.proto.NetworkEndpoint;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.ServiceContext;
import com.google.tsunami.proto.Software;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.Version;
import com.google.tsunami.proto.Version.VersionType;
import com.google.tsunami.proto.VersionSet;
import com.google.tsunami.proto.WebServiceContext;
import java.io.IOException;
import java.util.Collection;
import java.util.List;
import javax.inject.Inject;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for {@link WebServiceFingerprinter}. */
@RunWith(JUnit4.class)
public final class WebServiceFingerprinterTest {

  private final FakeCrawler fakeCrawler = new FakeCrawler();
  private WebServiceFingerprinterCliOptions cliOptions;
  private MockWebServer mockWebServer;

  @Inject WebServiceFingerprinter fingerprinter;

  @Before
  public void setUp() {
    cliOptions = new WebServiceFingerprinterCliOptions();
    mockWebServer = new MockWebServer();
    Guice.createInjector(
            new AbstractModule() {
              @Override
              protected void configure() {
                bind(Crawler.class).toInstance(fakeCrawler);
                bind(WebServiceFingerprinterCliOptions.class).toInstance(cliOptions);
                install(new FactoryModuleBuilder().build(VersionDetector.Factory.class));
                install(new HttpClientModule.Builder().build());
              }

              @Provides
              ImmutableMap<SoftwareIdentity, FingerprintData> provideFingerprints() {
                return ImmutableMap.of(
                    SOFTWARE_IDENTITY_1,
                    FINGERPRINT_DATA_1,
                    SOFTWARE_IDENTITY_2,
                    FINGERPRINT_DATA_2,
                    SOFTWARE_IDENTITY_3,
                    FINGERPRINT_DATA_3);
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
                        ImmutableList.of("1.0"),
                        ImmutableList.of()))
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
                        ImmutableList.of("1.0"),
                        ImmutableList.of()))
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
                        ImmutableList.of("1.0"),
                        ImmutableList.of()))
                .addNetworkServices(
                    addServiceContext(
                        networkService,
                        "/",
                        SOFTWARE_IDENTITY_2.getSoftware(),
                        ImmutableList.of("2.0", "2.1"),
                        ImmutableList.of()))
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

  @Test
  public void fingerprint_whenCrawlResultsWithZipContent_doNotRecordCrawlResult() {
    fakeCrawler.setCrawlResults(ImmutableSet.of(SOFTWARE_3_CSS, SOFTWARE_3_ZIP));
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
                        SOFTWARE_IDENTITY_3.getSoftware(),
                        ImmutableList.of("2.1"),
                        ImmutableList.of()))
                .build());
  }

  @Test
  public void fingerprint_defaultZipContentExclusion_doNotRecordCrawlResult() {
    fakeCrawler.setCrawlResults(ImmutableSet.of(SOFTWARE_3_CSS, SOFTWARE_3_ZIP));
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
                        SOFTWARE_IDENTITY_3.getSoftware(),
                        ImmutableList.of("2.1"),
                        ImmutableList.of(
                            CrawlResult.newBuilder()
                                .setCrawlTarget(
                                    CrawlTarget.newBuilder()
                                        .setUrl(fakeUrl("/file.css"))
                                        .setHttpMethod("GET"))
                                .setContentType("text/css")
                                .build())))
                .build());
    assertThat(
            fingerprintingReport
                .getNetworkServices(0)
                .getServiceContext()
                .getWebServiceContext()
                .getCrawlResultsList())
        .doesNotContain(SOFTWARE_3_ZIP);
  }

  @Test
  public void fingerprint_whenLimitContentSize_doNotRecordLargeCrawlResult() {
    cliOptions.maxRecordingContentSize = 50L;
    fakeCrawler.setCrawlResults(ImmutableSet.of(SOFTWARE_3_CSS, SOFTWARE_3_ZIP));
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
                        SOFTWARE_IDENTITY_3.getSoftware(),
                        ImmutableList.of("2.1"),
                        ImmutableList.of()))
                .build());
    assertThat(
            fingerprintingReport
                .getNetworkServices(0)
                .getServiceContext()
                .getWebServiceContext()
                .getCrawlResultsList())
        .doesNotContain(SOFTWARE_3_CSS);
  }

  @Test
  public void fingerprint_mlflowServiceWithBasicAuth_fillsServiceContextWithApplication()
      throws Exception {
    fakeCrawler.setCrawlResults(ImmutableSet.of(SOFTWARE_4_MLFLOW));
    startMockMlflowWebServer();
    NetworkEndpoint endpoint =
        forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort());
    NetworkService networkService =
        NetworkService.newBuilder().setNetworkEndpoint(endpoint).setServiceName("http").build();

    FingerprintingReport fingerprintingReport =
        fingerprinter.fingerprint(TargetInfo.getDefaultInstance(), networkService);

    assertThat(fingerprintingReport)
        .comparingExpectedFieldsOnly()
        .isEqualTo(
            FingerprintingReport.newBuilder()
                .addNetworkServices(
                    networkService.toBuilder()
                        .setServiceName(SOFTWARE_IDENTITY_4.getSoftware())
                        .setServiceContext(
                            ServiceContext.newBuilder()
                                .setWebServiceContext(
                                    WebServiceContext.newBuilder()
                                        .setApplicationRoot(
                                            String.format(
                                                "http://%s/",
                                                NetworkEndpointUtils.toUriAuthority(endpoint)))
                                        .setSoftware(
                                            Software.newBuilder()
                                                .setName(SOFTWARE_IDENTITY_4.getSoftware())))))
                .build());
  }

  private void startMockMlflowWebServer() throws IOException {
    final Dispatcher dispatcher =
        new Dispatcher() {
          final MockResponse unauthorizedResponse =
              new MockResponse()
                  .setResponseCode(401)
                  .setBody(
                      "You are not authenticated. "
                          + "Please see https://www.mlflow.org/docs/latest/auth/index.html"
                          + "#authenticating-to-mlflow "
                          + "on how to authenticate");

          @Override
          public MockResponse dispatch(RecordedRequest request) {
            return unauthorizedResponse;
          }
        };
    mockWebServer.setDispatcher(dispatcher);
    mockWebServer.start();
    mockWebServer.url("/");
  }

  private static NetworkService addServiceContext(
      NetworkService networkService,
      String appRoot,
      String appName,
      Collection<String> versions,
      List<CrawlResult> crawlResults) {
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
                        .setVersionSet(versionSet)
                        .addAllCrawlResults(crawlResults)))
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
