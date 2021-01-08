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

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableSet.toImmutableSet;
import static com.google.common.util.concurrent.MoreExecutors.directExecutor;

import com.google.common.collect.ImmutableSet;
import com.google.common.flogger.GoogleLogger;
import com.google.common.util.concurrent.Futures;
import com.google.common.util.concurrent.ListenableFuture;
import com.google.common.util.concurrent.ListeningExecutorService;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpMethod;
import com.google.tsunami.proto.CrawlConfig;
import com.google.tsunami.proto.CrawlResult;
import com.google.tsunami.proto.CrawlTarget;
import java.util.concurrent.ForkJoinPool;
import javax.inject.Inject;

/**
 * A simple multithreaded implementation for a web crawler.
 *
 * <p>Under the hood this crawler assigns initial crawling tasks for the seeding URLs into a {@link
 * ForkJoinPool}. Each worker thread in the pool will crawl one single URL, spawn and assign more
 * crawling tasks back into the pool based on the links extracted from the crawled web resources.
 */
public final class SimpleCrawler implements Crawler {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private final ForkJoinPool forkJoinPool;
  private final ListeningExecutorService schedulingPool;
  private final HttpClient httpClient;

  @Inject
  SimpleCrawler(
      @SimpleCrawlerWorkerPool ForkJoinPool forkJoinPool,
      @SimpleCrawlerSchedulingPool ListeningExecutorService schedulingPool,
      HttpClient httpClient) {
    this.forkJoinPool = checkNotNull(forkJoinPool);
    this.schedulingPool = checkNotNull(schedulingPool);
    this.httpClient = checkNotNull(httpClient).modify().setFollowRedirects(false).build();
  }

  @Override
  public ListenableFuture<ImmutableSet<CrawlResult>> crawlAsync(CrawlConfig crawlConfig) {
    // A global state shared across all crawling worker thread.
    SimpleCrawlerResults crawlerResults = new SimpleCrawlerResults();
    CrawlConfig crawlConfigWithScopes = CrawlConfigUtils.createDefaultScopesIfAbsent(crawlConfig);

    // Starts crawling action on each seeding URL and ignores crawling errors.
    ImmutableSet<ListenableFuture<Void>> crawlActionFutures =
        crawlConfig.getSeedingUrlsList().stream()
            .map(seedingUrl -> buildCrawlAction(crawlConfigWithScopes, seedingUrl, crawlerResults))
            .map(crawlAction -> startCrawlAction(crawlAction, schedulingPool))
            .collect(toImmutableSet());
    return Futures.whenAllComplete(crawlActionFutures)
        .call(crawlerResults::getFinalResults, schedulingPool);
  }

  private SimpleCrawlAction buildCrawlAction(
      CrawlConfig crawlConfig, String url, SimpleCrawlerResults crawlerResults) {
    CrawlTarget crawlTarget =
        CrawlTarget.newBuilder().setHttpMethod(HttpMethod.GET.toString()).setUrl(url).build();
    return new SimpleCrawlAction(0, httpClient, crawlConfig, crawlTarget, crawlerResults);
  }

  private ListenableFuture<Void> startCrawlAction(
      SimpleCrawlAction crawlAction, ListeningExecutorService executorService) {
    return Futures.catching(
        // Start a crawling action on the working pool and assign a thread in executorService to
        // wait for the result.
        executorService.submit(() -> forkJoinPool.invoke(crawlAction)),
        // Simple crawler simply swallows all exceptions from the worker pool and ignore the errored
        // seed.
        Throwable.class,
        throwable -> {
          logger.atWarning().withCause(throwable).log(
              "Simple crawler failed crawling seeding url '%s', seed is ignored.",
              crawlAction.getTargetUrl());
          return null;
        },
        directExecutor());
  }
}
