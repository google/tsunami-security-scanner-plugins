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
import static com.google.common.truth.Truth.assertThat;

import com.google.common.collect.ImmutableList;
import com.google.common.util.concurrent.Uninterruptibles;
import com.google.tsunami.proto.CrawlTarget;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.ForkJoinTask;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.IntStream;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for {@link SimpleCrawlerResults}. */
@RunWith(JUnit4.class)
public final class SimpleCrawlerResultsTest {

  @Test
  public void recordNewCrawlIfNotVisited_always_returnsNonEmptyOptionalForOnlyOneThread() {
    CountDownLatch latch = new CountDownLatch(1);
    AtomicInteger threadCounter = new AtomicInteger(0);
    SimpleCrawlerResults results = new SimpleCrawlerResults();

    ImmutableList<ForkJoinTask<?>> tasks =
        IntStream.range(0, 10000)
            .mapToObj(
                unusedInt ->
                    ForkJoinPool.commonPool()
                        .submit(
                            () -> {
                              Uninterruptibles.awaitUninterruptibly(latch);
                              results
                                  .recordNewCrawlIfNotVisited(CrawlTarget.getDefaultInstance())
                                  .ifPresent(unused -> threadCounter.incrementAndGet());
                            }))
            .collect(toImmutableList());
    latch.countDown();
    tasks.forEach(ForkJoinTask::join);

    assertThat(threadCounter.get()).isEqualTo(1);
  }
}
