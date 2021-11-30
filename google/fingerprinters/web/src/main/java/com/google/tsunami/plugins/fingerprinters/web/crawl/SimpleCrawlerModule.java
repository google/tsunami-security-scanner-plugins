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

import com.google.inject.AbstractModule;
import com.google.inject.Provides;
import com.google.tsunami.common.concurrent.ThreadPoolModule;
import java.time.Duration;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.ForkJoinPool.ForkJoinWorkerThreadFactory;
import java.util.concurrent.ForkJoinWorkerThread;
import java.util.concurrent.atomic.AtomicInteger;

/** Guice module for installing the {@link SimpleCrawler} and dependencies. */
public final class SimpleCrawlerModule extends AbstractModule {
  private final int maxActiveThreads;
  private final SimpleCrawlerWorkerThreadFactory threadFactory;

  public SimpleCrawlerModule(int maxActiveThreads) {
    this.maxActiveThreads = maxActiveThreads;
    this.threadFactory = new SimpleCrawlerWorkerThreadFactory(maxActiveThreads);
  }

  @Override
  protected void configure() {
    bind(Crawler.class).to(SimpleCrawler.class);
    install(
        new ThreadPoolModule.Builder()
            .setName("SimpleCrawlerSchedulingPool")
            .setCoreSize(maxActiveThreads)
            .setMaxSize(maxActiveThreads)
            .setQueueCapacity(maxActiveThreads)
            .setDaemon(true)
            .setDelayedShutdown(Duration.ofMinutes(1))
            .setPriority(Thread.NORM_PRIORITY)
            .setAnnotation(SimpleCrawlerSchedulingPool.class)
            .build());
  }

  @Provides
  @SimpleCrawlerWorkerPool
  ForkJoinPool providesSimpleCrawlerWorkerPool() {
    return new ForkJoinPool(maxActiveThreads, threadFactory, null, false);
  }

  /**
   * A {@link ForkJoinWorkerThreadFactory} implementation for executing {@link SimpleCrawler} tasks.
   *
   * <p>This implementation follows the discussion thread on "ForkJoinPool cap on number of threads"
   * (see http://cs.oswego.edu/pipermail/concurrency-interest/2015-March/014187.html) to add a cap
   * on the number of running threads by supplying a custom thread pool that returns null when the
   * cap is exceeded.
   *
   * <p>We don't provide a general {@link com.google.tsunami.common.concurrent.ThreadPoolModule}
   * variant for {@link ForkJoinPool} in Tsunami's codebase as we don't expect other use cases for
   * it in any foreseeable future.
   *
   * TODO: replace this with the new JDK9 ForkJoinPool constructor once Tsunami is Java 11 ready.
   */
  private static final class SimpleCrawlerWorkerThreadFactory
      implements ForkJoinWorkerThreadFactory {
    private final int maxActiveThreads;
    private final AtomicInteger threadCounter = new AtomicInteger();
    private final AtomicInteger activeThreads = new AtomicInteger();

    SimpleCrawlerWorkerThreadFactory(int maxActiveThreads) {
      this.maxActiveThreads = maxActiveThreads;
    }

    @Override
    public ForkJoinWorkerThread newThread(ForkJoinPool pool) {
      int currentActive;
      do {
        currentActive = activeThreads.get();
        if (currentActive >= maxActiveThreads) {
          // Reject requests by returning null to enforce the cap on worker threads.
          return null;
        }
      } while (!activeThreads.compareAndSet(currentActive, currentActive + 1));

      ForkJoinWorkerThread thread =
          new ForkJoinWorkerThread(pool) {
            @Override
            protected void onTermination(Throwable exception) {
              activeThreads.decrementAndGet();
              super.onTermination(exception);
            }
          };
      thread.setName("SimpleCrawlerWorkerThread-" + threadCounter.getAndIncrement());
      thread.setDaemon(true);
      return thread;
    }
  }
}
