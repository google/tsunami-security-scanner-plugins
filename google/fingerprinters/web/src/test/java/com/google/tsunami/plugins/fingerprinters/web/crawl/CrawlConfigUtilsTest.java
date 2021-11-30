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

import com.google.tsunami.proto.CrawlConfig;
import com.google.tsunami.proto.CrawlConfig.Scope;
import com.google.tsunami.proto.CrawlTarget;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for {@link CrawlConfigUtils}. */
@RunWith(JUnit4.class)
public final class CrawlConfigUtilsTest {

  @Test
  public void createDefaultScopesIfAbsent_withScopesAlreadySet_usesExistingScopes() {
    CrawlConfig crawlConfig =
        CrawlConfig.newBuilder()
            .addScopes(Scope.getDefaultInstance())
            .addSeedingUrls("http://localhost:8080")
            .build();

    assertThat(CrawlConfigUtils.createDefaultScopesIfAbsent(crawlConfig)).isEqualTo(crawlConfig);
  }

  @Test
  public void createDefaultScopesIfAbsent_withoutScopes_createDefaultScopes() {
    CrawlConfig crawlConfig =
        CrawlConfig.newBuilder()
            .addSeedingUrls("http://localhost:8080/path")
            .addSeedingUrls("http://localhost:8080/more/path/")
            .build();

    assertThat(CrawlConfigUtils.createDefaultScopesIfAbsent(crawlConfig))
        .isEqualTo(
            CrawlConfig.newBuilder()
                .addScopes(Scope.newBuilder().setDomain("localhost:8080").setPath("/path"))
                .addScopes(Scope.newBuilder().setDomain("localhost:8080").setPath("/more/path"))
                .addSeedingUrls("http://localhost:8080/path")
                .addSeedingUrls("http://localhost:8080/more/path/")
                .build());
  }

  @Test
  public void isCrawlTargetInScope_whenScopeEnforcementDisabled_alwaysReturnsTrue() {
    CrawlConfig crawlConfig =
        CrawlConfig.newBuilder()
            .addScopes(Scope.newBuilder().setDomain("localhost:8080").setPath("/in-scope"))
            .setShouldEnforceScopeCheck(false)
            .build();
    assertThat(
        CrawlConfigUtils.isCrawlTargetInScope(
            crawlConfig,
            CrawlTarget.newBuilder().setUrl("http://localhost:8080/in-scope/index.html").build()))
        .isTrue();
    assertThat(
        CrawlConfigUtils.isCrawlTargetInScope(
            crawlConfig,
            CrawlTarget.newBuilder().setUrl("http://localhost:8080/not-in-scope/index.html").build()))
        .isTrue();
  }

  @Test
  public void isCrawlTargetInScope_whenEnforcingScopeCheckAndTargetInScope_returnsTrue() {
    CrawlConfig crawlConfig =
        CrawlConfig.newBuilder()
            .addScopes(Scope.newBuilder().setDomain("localhost:8080").setPath("/path"))
            .addScopes(Scope.newBuilder().setDomain("localhost:8080").setPath("/more/path"))
            .setShouldEnforceScopeCheck(true)
            .build();

    assertThat(
            CrawlConfigUtils.isCrawlTargetInScope(
                crawlConfig,
                CrawlTarget.newBuilder().setUrl("http://localhost:8080/path/index.html").build()))
        .isTrue();
    assertThat(
            CrawlConfigUtils.isCrawlTargetInScope(
                crawlConfig,
                CrawlTarget.newBuilder().setUrl("http://localhost:8080/more/path/sub/url").build()))
        .isTrue();
  }

  @Test
  public void isCrawlTargetInScope_whenEnforcingScopeCheckAndTargetNotInScope_returnsFalse() {
    CrawlConfig crawlConfig =
        CrawlConfig.newBuilder()
            .addScopes(Scope.newBuilder().setDomain("localhost:8080").setPath("/path"))
            .addScopes(Scope.newBuilder().setDomain("localhost:8080").setPath("/more/path"))
            .setShouldEnforceScopeCheck(true)
            .build();

    assertThat(
            CrawlConfigUtils.isCrawlTargetInScope(
                crawlConfig, CrawlTarget.newBuilder().setUrl("http://localhost:8888/path").build()))
        .isFalse();
    assertThat(
            CrawlConfigUtils.isCrawlTargetInScope(
                crawlConfig,
                CrawlTarget.newBuilder().setUrl("http://localhost:8080/not-in-scope").build()))
        .isFalse();
    assertThat(
            CrawlConfigUtils.isCrawlTargetInScope(
                crawlConfig,
                CrawlTarget.newBuilder()
                    .setUrl("http://localhost:8080/more/not-in-scope/path")
                    .build()))
        .isFalse();
  }
}
