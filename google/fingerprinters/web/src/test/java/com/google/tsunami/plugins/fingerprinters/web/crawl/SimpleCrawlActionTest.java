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
package com.google.tsunami.plugins.fingerprinters.web.crawl;

import static com.google.common.truth.Truth.assertThat;
import static com.google.common.truth.extensions.proto.ProtoTruth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.common.io.Resources;
import com.google.inject.AbstractModule;
import com.google.inject.Guice;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.plugins.fingerprinters.web.WebServiceFingerprinterConfigs;
import com.google.tsunami.plugins.fingerprinters.web.WebServiceFingerprinterConfigs.WebServiceFingerprinterCliOptions;
import com.google.tsunami.plugins.fingerprinters.web.WebServiceFingerprinterConfigs.WebServiceFingerprinterConfigProperties;
import com.google.tsunami.proto.CrawlTarget;
import java.io.IOException;
import java.util.concurrent.ForkJoinPool;
import javax.inject.Inject;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for {@link SimpleCrawlAction}. */
@RunWith(JUnit4.class)
public final class SimpleCrawlActionTest {

  private HttpClient httpClient;
  private SimpleCrawlerResults crawlerResults;
  private MockWebServer mockWebServer;
  private TestDataBuilder dataBuilder;
  private WebServiceFingerprinterCliOptions cliOptions;
  private WebServiceFingerprinterConfigProperties configProperties;

  @Inject WebServiceFingerprinterConfigs configs;

  @Before
  public void setUp() {
    cliOptions = new WebServiceFingerprinterCliOptions();
    configProperties = new WebServiceFingerprinterConfigProperties();
    Guice.createInjector(
        new AbstractModule() {
          @Override
          protected void configure() {
            bind(WebServiceFingerprinterCliOptions.class).toInstance(cliOptions);
            bind(WebServiceFingerprinterConfigProperties.class)
                .toInstance(configProperties);
          }
        }
    ).injectMembers(this);
    httpClient =
        Guice.createInjector(
                new HttpClientModule.Builder().build())
            .getInstance(HttpClient.class)
            .modify()
            .setFollowRedirects(false)
            .build();
    crawlerResults = new SimpleCrawlerResults();
    mockWebServer = new MockWebServer();
    dataBuilder = TestDataBuilder.forMockServer(mockWebServer);
  }

  @After
  public void tearDown() throws IOException {
    mockWebServer.shutdown();
  }

  @Test
  public void getTargetUrl_always_returnsUrlFromCrawlTarget() {
    assertThat(
            new SimpleCrawlAction(
                    0,
                    httpClient,
                    dataBuilder.buildCrawlConfig(),
                    dataBuilder.buildCrawlTargetForSeedPath("/path"),
                    crawlerResults,
                    configs)
                .getTargetUrl())
        .isEqualTo(mockWebServer.url("/path").toString());
  }

  @Test
  public void compute_whenUrlAlreadyVisited_doesNotCrawlSameTarget() {
    crawlerResults.recordNewCrawlIfNotVisited(CrawlTarget.getDefaultInstance());

    ForkJoinPool.commonPool()
        .invoke(
            new SimpleCrawlAction(
                0,
                httpClient,
                dataBuilder.buildCrawlConfig(),
                CrawlTarget.getDefaultInstance(),
                crawlerResults,
                configs));

    assertThat(mockWebServer.getRequestCount()).isEqualTo(0);
  }

  @Test
  public void compute_whenTargetUrlIsInvalid_ignoresCrawlTarget() {
    ForkJoinPool.commonPool()
        .invoke(
            new SimpleCrawlAction(
                0,
                httpClient,
                dataBuilder.buildCrawlConfig(),
                dataBuilder.buildCrawlTargetForSeedPath("").toBuilder()
                    .setUrl("invalid-url")
                    .build(),
                crawlerResults,
                configs));

    assertThat(mockWebServer.getRequestCount()).isEqualTo(0);
    assertThat(crawlerResults.getFinalResults()).isEmpty();
  }

  @Test
  public void compute_whenHttpRequestError_ignoresCrawlTarget() {
    ForkJoinPool.commonPool()
        .invoke(
            new SimpleCrawlAction(
                0,
                httpClient,
                dataBuilder.buildCrawlConfig(),
                dataBuilder.buildCrawlTargetForSeedPath("/timeout").toBuilder().build(),
                crawlerResults,
                configs));

    assertThat(mockWebServer.getRequestCount()).isEqualTo(1);
    assertThat(crawlerResults.getFinalResults()).isEmpty();
  }

  @Test
  public void compute_whenSeedingUrlRedirects_followsRedirect() throws IOException {
    String body =
        Resources.toString(
            Resources.getResource(this.getClass(), "testdata/pageWithLinks.html"), UTF_8);
    mockWebServer.setDispatcher(new FakeServerDispatcher(body));

    ForkJoinPool.commonPool()
        .invoke(
            new SimpleCrawlAction(
                0,
                httpClient,
                dataBuilder.buildCrawlConfig(),
                dataBuilder.buildCrawlTargetForSeedPath("/redirect"),
                crawlerResults,
                configs));

    assertThat(crawlerResults.getFinalResults())
        .containsExactly(
            dataBuilder.buildRedirectCrawlResult(0, "/redirect"),
            dataBuilder.buildCrawlResult(1, "/", body),
            dataBuilder.buildCrawlResult(2, "/anchor-link", "anchor-link-response"),
            dataBuilder.buildCrawlResult(2, "/img-src", "img-src-response"));
  }

  @Test
  public void compute_whenSeedingUrlReturnsValidHtmlPage_followsAllLinksOnPage() throws Exception {
    assetCrawlResults("testdata/pageWithLinks.html");
  }

  @Test
  public void compute_whenExceedsMaxDepth_stopsCrawlingAtMaxDepth() throws IOException {
    String body =
        Resources.toString(
            Resources.getResource(this.getClass(), "testdata/pageWithLinks.html"), UTF_8);
    mockWebServer.setDispatcher(new FakeServerDispatcher(body));

    ForkJoinPool.commonPool()
        .invoke(
            new SimpleCrawlAction(
                0,
                httpClient,
                dataBuilder.buildCrawlConfig().toBuilder().setMaxDepth(1).build(),
                dataBuilder.buildCrawlTargetForSeedPath("/redirect"),
                crawlerResults,
                configs));

    assertThat(crawlerResults.getFinalResults())
        .containsExactly(
            dataBuilder.buildRedirectCrawlResult(0, "/redirect"),
            dataBuilder.buildCrawlResult(1, "/", body));
  }

  @Test
  public void compute_whenHtmlPageContainsOutOfScopeLink_ignoresOutOfScopeLink()
      throws IOException {
    String body =
        Resources.toString(
            Resources.getResource(this.getClass(), "testdata/pageWithOutOfScopeLinks.html"), UTF_8);
    mockWebServer.setDispatcher(new FakeServerDispatcher(body));

    ForkJoinPool.commonPool()
        .invoke(
            new SimpleCrawlAction(
                0,
                httpClient,
                dataBuilder.buildCrawlConfig(),
                dataBuilder.buildCrawlTargetForSeedPath("/"),
                crawlerResults,
                configs));

    assertThat(crawlerResults.getFinalResults())
        .containsExactly(dataBuilder.buildCrawlResult(0, "/", body));
  }

  @Test
  public void compute_whenTargetUrlContainLocalHost_normalizeHost() throws Exception {
    assetCrawlResults("testdata/pageWithLocalhostLinks.html");
  }

  private void assetCrawlResults(String testdataResourceName) throws Exception {
    String body =
        Resources.toString(Resources.getResource(this.getClass(), testdataResourceName), UTF_8);
    mockWebServer.setDispatcher(new FakeServerDispatcher(body));

    ForkJoinPool.commonPool()
        .invoke(
            new SimpleCrawlAction(
                0,
                httpClient,
                dataBuilder.buildCrawlConfig(),
                dataBuilder.buildCrawlTargetForSeedPath("/"),
                crawlerResults,
                configs));

    assertThat(crawlerResults.getFinalResults())
        .containsExactly(
            dataBuilder.buildCrawlResult(0, "/", body),
            dataBuilder.buildCrawlResult(1, "/anchor-link", "anchor-link-response"),
            dataBuilder.buildCrawlResult(1, "/img-src", "img-src-response"));
  }
}
