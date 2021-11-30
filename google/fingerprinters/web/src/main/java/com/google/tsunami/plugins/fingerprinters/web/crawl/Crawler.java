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

import com.google.common.collect.ImmutableSet;
import com.google.common.util.concurrent.ListenableFuture;
import com.google.tsunami.proto.CrawlConfig;
import com.google.tsunami.proto.CrawlResult;
import java.util.concurrent.ExecutionException;

/**
 * A crawler starts from several seeding URLs and recursively fetches web content by following
 * reachable links extracted from the requested resources.
 */
public interface Crawler {

  /**
   * Performs the crawling action based on the given {@code crawlConfig}.
   *
   * @param crawlConfig config for this crawling action
   * @return all the fetched web contents.
   */
  default ImmutableSet<CrawlResult> crawl(CrawlConfig crawlConfig) {
    try {
      return crawlAsync(crawlConfig).get();
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new CrawlerException("Crawler got interrupted.", e);
    } catch (ExecutionException e) {
      throw new CrawlerException("Crawler failed crawling with unexpected error.", e);
    }
  }

  /**
   * Performs the crawling action based on the given {@code crawlConfig}, asynchronously.
   *
   * @param crawlConfig config for this crawling action
   * @return all the fetched web contents.
   */
  ListenableFuture<ImmutableSet<CrawlResult>> crawlAsync(CrawlConfig crawlConfig);
}
