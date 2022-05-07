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
import static com.google.tsunami.plugins.fingerprinters.web.common.CrawlUtils.buildCrawlResult;

import com.google.common.base.Strings;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Streams;
import com.google.common.flogger.GoogleLogger;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpMethod;
import com.google.tsunami.common.net.http.HttpRequest;
import com.google.tsunami.common.net.http.HttpResponse;
import com.google.tsunami.proto.CrawlConfig;
import com.google.tsunami.proto.CrawlResult;
import com.google.tsunami.proto.CrawlTarget;
import com.google.tsunami.proto.NetworkService;
import java.util.Optional;
import java.util.concurrent.RecursiveAction;
import java.util.stream.Stream;
import okhttp3.HttpUrl;

/**
 * A {@link RecursiveAction} that crawls a single web target.
 *
 * <p>The {@link SimpleCrawlAction} performs the crawling in the following fashion:
 *
 * <ol>
 *   <li>Check whether the given target has already been visited. If so, {@link SimpleCrawlAction}
 *       does nothing.
 *   <li>If the target is a new target, send HTTP request to the target to retrieve the web
 *       resources serviced on the target.
 *   <li>Fill HTTP response data into {@link CrawlResult} protobuf.
 *   <li>Extract links HTTP response headers and response body.
 *   <li>For each links from HTTP response, create a new {@link SimpleCrawlAction} on the link
 *       target and invoke all new actions. (This blocking recursive call is OK in a {@link
 *       RecursiveAction} and {@link java.util.concurrent.ForkJoinPool}.
 * </ol>
 */
final class SimpleCrawlAction extends RecursiveAction {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private final int currentDepth;
  private final HttpClient httpClient;
  private final CrawlConfig crawlConfig;
  private final CrawlTarget crawlTarget;
  private final SimpleCrawlerResults crawlerResults;

  SimpleCrawlAction(
      int currentDepth,
      HttpClient httpClient,
      CrawlConfig crawlConfig,
      CrawlTarget crawlTarget,
      SimpleCrawlerResults crawlerResults) {
    this.currentDepth = currentDepth;
    this.httpClient = checkNotNull(httpClient);
    this.crawlConfig = checkNotNull(crawlConfig);
    this.crawlTarget = checkNotNull(crawlTarget);
    this.crawlerResults = checkNotNull(crawlerResults);
  }

  String getTargetUrl() {
    return crawlTarget.getUrl();
  }

  @Override
  protected void compute() {
    crawlerResults
        .recordNewCrawlIfNotVisited(crawlTarget)
        .ifPresent(
            crawlResultBuilder -> {
              try {
                // This is a new CrawlTarget, performs the crawl and spawn new actions for the links
                // extracted from the crawl response.
                HttpResponse httpResponse =
                    httpClient.send(
                        buildHttpRequest(crawlTarget),
                        NetworkService.newBuilder()
                            .setNetworkEndpoint(crawlConfig.getNetworkEndpoint())
                            .build());
                logger.atInfo().log(
                    "SimpleCrawlAction visited target '%s' with method '%s' at depth '%d',"
                        + " response code: %d.",
                    crawlTarget.getUrl(),
                    crawlTarget.getHttpMethod(),
                    currentDepth,
                    httpResponse.status().code());

                crawlResultBuilder.mergeFrom(
                    buildCrawlResult(crawlTarget, currentDepth, httpResponse));
                spawnNewCrawlActions(httpResponse);
              } catch (Throwable e) {
                // Ignore all errors here as we don't try to recover. Failed crawl targets are
                // simply ignored.
                logger.atWarning().withCause(e).log(
                    "SimpleCrawlAction cannot reach web resources at '%s', crawl target skipped.",
                    crawlTarget.getUrl());
              }
            });
  }

  private static HttpRequest buildHttpRequest(CrawlTarget crawlTarget) {
    HttpUrl targetUrl = HttpUrl.parse(crawlTarget.getUrl());
    if (targetUrl == null) {
      throw new IllegalArgumentException(
          String.format(
              "SimpleCrawlAction received a target with an invalid URL ('%s')",
              crawlTarget.getUrl()));
    }

    return HttpRequest.builder()
        .setMethod(HttpMethod.valueOf(crawlTarget.getHttpMethod()))
        .setUrl(targetUrl)
        .withEmptyHeaders()
        .build();
  }

  private void spawnNewCrawlActions(HttpResponse httpResponse) {
    // Stop crawling when the action reaches the max crawling depth.
    if (currentDepth >= crawlConfig.getMaxDepth()) {
      return;
    }

    HttpUrl baseUrl = HttpUrl.parse(crawlTarget.getUrl());
    ImmutableSet<SimpleCrawlAction> newCrawlActions =
        // Get new crawl targets from both HTTP headers and response body.
        Streams.concat(
                CrawlTargetUtils.extractFromHeaders(httpResponse.headers(), baseUrl).stream(),
                httpResponse
                    .bodyString()
                    .map(body -> CrawlTargetUtils.extractFromHtml(body, baseUrl).stream())
                    .orElse(Stream.empty()))
            // Ignore invalid CrawlTarget urls.
            .filter(SimpleCrawlAction::isValidCrawlTarget)
            // Ignore out-of-scope URLs.
            .filter(crawlTarget -> CrawlConfigUtils.isCrawlTargetInScope(crawlConfig, crawlTarget))
            .map(this::newCrawlAction)
            .collect(toImmutableSet());
    invokeAll(newCrawlActions);
  }

  private static boolean isValidCrawlTarget(CrawlTarget crawlTarget) {
    return Optional.ofNullable(HttpUrl.parse(crawlTarget.getUrl()))
        .map(httpUrl -> !Strings.isNullOrEmpty(httpUrl.host()))
        .orElse(false);
  }

  private SimpleCrawlAction newCrawlAction(CrawlTarget newCrawlTarget) {
    return new SimpleCrawlAction(
        currentDepth + 1, httpClient, crawlConfig, newCrawlTarget, crawlerResults);
  }
}
