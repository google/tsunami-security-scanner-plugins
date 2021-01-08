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

import static com.google.common.collect.ImmutableSet.toImmutableSet;

import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Maps;
import com.google.tsunami.proto.CrawlResult;
import com.google.tsunami.proto.CrawlTarget;
import java.util.Optional;
import java.util.concurrent.ConcurrentMap;

/** A thread safe crawl results holder for {@link SimpleCrawler}. */
final class SimpleCrawlerResults {
  private final ConcurrentMap<CrawlTarget, CrawlResult.Builder> crawlResultBuilderMap =
      Maps.newConcurrentMap();

  ImmutableSet<CrawlResult> getFinalResults() {
    return crawlResultBuilderMap.values().stream()
        .map(CrawlResult.Builder::build)
        .filter(crawlResult -> !crawlResult.equals(CrawlResult.getDefaultInstance()))
        .collect(toImmutableSet());
  }

  /**
   * Records a potentially new crawling target if the target hasn't been visited by other crawling
   * worker yet. This method guarantees that only one crawling worker thread gets the created
   * CrawlResult builder.
   */
  Optional<CrawlResult.Builder> recordNewCrawlIfNotVisited(CrawlTarget crawlTarget) {
    CrawlResult.Builder newCrawlResultBuilder = CrawlResult.newBuilder();
    return crawlResultBuilderMap.putIfAbsent(crawlTarget, newCrawlResultBuilder) == null
        ? Optional.of(newCrawlResultBuilder)
        : Optional.empty();
  }
}
