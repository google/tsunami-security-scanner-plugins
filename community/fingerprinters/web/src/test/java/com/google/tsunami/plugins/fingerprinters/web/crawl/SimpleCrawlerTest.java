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

import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.common.truth.extensions.proto.ProtoTruth.assertThat;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.inject.AbstractModule;
import com.google.inject.Guice;
import com.google.inject.Provides;
import com.google.tsunami.common.concurrent.ThreadPoolModule;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.proto.CrawlConfig;
import com.google.tsunami.proto.CrawlResult;
import java.io.IOException;
import java.util.Collection;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.ForkJoinTask;
import javax.inject.Inject;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for {@link SimpleCrawler}. */
@RunWith(JUnit4.class)
public final class SimpleCrawlerTest {
  @Inject SimpleCrawler simpleCrawler;

  private MockWebServer mockWebServer;
  private TestDataBuilder dataBuilder;

  @Before
  public void setUp() {
    mockWebServer = new MockWebServer();
    dataBuilder = TestDataBuilder.forMockServer(mockWebServer);

    Guice.createInjector(new SimpleCrawlerModule(1), new HttpClientModule.Builder().build())
        .injectMembers(this);
  }

  @After
  public void tearDown() throws IOException {
    mockWebServer.shutdown();
  }

  @Test
  public void crawlAsync_whenNoSeedingUrl_returnsEmptySet()
      throws ExecutionException, InterruptedException {
    ImmutableSet<CrawlResult> crawlResults =
        simpleCrawler.crawlAsync(CrawlConfig.getDefaultInstance()).get();

    assertThat(crawlResults).isEmpty();
  }

  @Test
  public void crawlAsync_whenSingleSeedingUrl_startsSingleCrawlAction()
      throws ExecutionException, InterruptedException {
    mockWebServer.setDispatcher(new FakeServerDispatcher(""));

    ImmutableSet<CrawlResult> crawlResults =
        simpleCrawler.crawlAsync(buildTestCrawlConfig(ImmutableList.of("/img-src"))).get();

    assertThat(crawlResults)
        .containsExactly(dataBuilder.buildCrawlResult(0, "/img-src", "img-src-response"));
  }

  @Test
  public void crawlAsync_whenMultipleSeedingUrl_startsMultipleCrawlActions()
      throws ExecutionException, InterruptedException {
    mockWebServer.setDispatcher(new FakeServerDispatcher(""));

    ImmutableSet<CrawlResult> crawlResults =
        simpleCrawler
            .crawlAsync(buildTestCrawlConfig(ImmutableList.of("/anchor-link", "/img-src")))
            .get();

    assertThat(crawlResults)
        .containsExactly(
            dataBuilder.buildCrawlResult(0, "/anchor-link", "anchor-link-response"),
            dataBuilder.buildCrawlResult(0, "/img-src", "img-src-response"));
  }

  @Test
  public void crawlAsync_whenCrawlFailedForSeedingUrl_ignoresSeedingUrl()
      throws ExecutionException, InterruptedException {
    simpleCrawler =
        Guice.createInjector(
                new HttpClientModule.Builder().build(),
                new ThrowingForkJoinPoolModule(),
                new ThreadPoolModule.Builder()
                    .setName("test")
                    .setMaxSize(1)
                    .setQueueCapacity(1)
                    .setAnnotation(SimpleCrawlerSchedulingPool.class)
                    .build())
            .getInstance(SimpleCrawler.class);
    mockWebServer.setDispatcher(new FakeServerDispatcher(""));

    ImmutableSet<CrawlResult> crawlResults =
        simpleCrawler.crawlAsync(buildTestCrawlConfig(ImmutableList.of("/img-src"))).get();

    assertThat(crawlResults).isEmpty();
  }

  private CrawlConfig buildTestCrawlConfig(Collection<String> seedingPath) {
    return dataBuilder.buildCrawlConfig().toBuilder()
        // Make sure each action doesn't follow URLs and always exit after visiting one URL.
        .setMaxDepth(0)
        .addAllSeedingUrls(
            seedingPath.stream()
                .map(path -> mockWebServer.url(path).toString())
                .collect(toImmutableList()))
        .build();
  }

  private static final class ThrowingForkJoinPoolModule extends AbstractModule {
    @Provides
    @SimpleCrawlerWorkerPool
    public ForkJoinPool provideThrowingForkJoinPool() {
      return new ForkJoinPool() {
        @Override
        public <T> T invoke(ForkJoinTask<T> task) {
          throw new RuntimeException();
        }
      };
    }
  }
}
