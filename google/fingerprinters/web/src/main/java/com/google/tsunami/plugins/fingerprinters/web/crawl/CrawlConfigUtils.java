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

import com.google.tsunami.proto.CrawlConfig;
import com.google.tsunami.proto.CrawlTarget;

/** Static utility methods pertaining to {@link CrawlConfig} proto buffer. */
final class CrawlConfigUtils {
  private CrawlConfigUtils() {}

  static CrawlConfig createDefaultScopesIfAbsent(CrawlConfig crawlConfig) {
    if (crawlConfig.getScopesCount() > 0) {
      return crawlConfig;
    }

    return CrawlConfig.newBuilder(crawlConfig)
        .addAllScopes(
            crawlConfig.getSeedingUrlsList().stream()
                .map(ScopeUtils::fromUrl)
                .collect(toImmutableList()))
        .build();
  }

  static boolean isCrawlTargetInScope(CrawlConfig crawlConfig, CrawlTarget crawlTarget) {
    return !crawlConfig.getShouldEnforceScopeCheck() || crawlConfig.getScopesList().stream()
        .anyMatch(scope -> ScopeUtils.isInScope(scope, crawlTarget.getUrl()));
  }
}
