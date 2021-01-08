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
import static org.junit.Assert.assertThrows;

import com.google.tsunami.proto.CrawlConfig.Scope;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for {@link ScopeUtils}. */
@RunWith(JUnit4.class)
public final class ScopeUtilsTest {

  @Test
  public void isInScope_withInvalidUrl_throwsIllegalArgumentException() {
    assertThrows(
        IllegalArgumentException.class,
        () -> ScopeUtils.isInScope(ScopeUtils.fromUrl("http://www.google.com"), "invalid_url"));
  }

  @Test
  public void isIsScope_withEmptyScopePath_matchesArbitraryPathsOnSameDomain() {
    Scope scope = Scope.newBuilder().setDomain("google.com").setPath("").build();

    assertThat(ScopeUtils.isInScope(scope, "http://google.com")).isTrue();
    assertThat(ScopeUtils.isInScope(scope, "http://google.com/")).isTrue();
    assertThat(ScopeUtils.isInScope(scope, "http://google.com/path")).isTrue();
    assertThat(ScopeUtils.isInScope(scope, "http://subdomain.google.com/some/long/path")).isTrue();
  }

  @Test
  public void isIsScope_withEmptyScopePath_doesNotMatchOtherDomains() {
    Scope scope = Scope.newBuilder().setDomain("google.com").setPath("").build();

    assertThat(ScopeUtils.isInScope(scope, "http://nongoogle.com")).isFalse();
    assertThat(ScopeUtils.isInScope(scope, "http://nongoogle.com/")).isFalse();
    assertThat(ScopeUtils.isInScope(scope, "http://nongoogle.com/path")).isFalse();
    assertThat(ScopeUtils.isInScope(scope, "http://subdomain.nongoogle.com/some/long/path"))
        .isFalse();
  }

  @Test
  public void isIsScope_withSlashScopePath_matchesArbitraryPathsOnSameDomain() {
    Scope scope = Scope.newBuilder().setDomain("google.com").setPath("/").build();

    assertThat(ScopeUtils.isInScope(scope, "http://google.com")).isTrue();
    assertThat(ScopeUtils.isInScope(scope, "http://google.com/")).isTrue();
    assertThat(ScopeUtils.isInScope(scope, "http://google.com/path")).isTrue();
    assertThat(ScopeUtils.isInScope(scope, "http://subdomain.google.com/some/long/path")).isTrue();
  }

  @Test
  public void isIsScope_withSlashScopePath_doesNotMatchOtherDomains() {
    Scope scope = Scope.newBuilder().setDomain("google.com").setPath("/").build();

    assertThat(ScopeUtils.isInScope(scope, "http://nongoogle.com")).isFalse();
    assertThat(ScopeUtils.isInScope(scope, "http://nongoogle.com/")).isFalse();
    assertThat(ScopeUtils.isInScope(scope, "http://nongoogle.com/path")).isFalse();
    assertThat(ScopeUtils.isInScope(scope, "http://subdomain.nongoogle.com/some/long/path"))
        .isFalse();
  }

  @Test
  public void isIsScope_withNonEmptyScopePath_matchesSubPathsOnSameDomain() {
    Scope scope = Scope.newBuilder().setDomain("google.com").setPath("/path").build();

    assertThat(ScopeUtils.isInScope(scope, "http://google.com")).isFalse();
    assertThat(ScopeUtils.isInScope(scope, "http://google.com/")).isFalse();
    assertThat(ScopeUtils.isInScope(scope, "http://google.com/path")).isTrue();
    assertThat(ScopeUtils.isInScope(scope, "http://google.com/path/")).isTrue();
    assertThat(ScopeUtils.isInScope(scope, "http://subdomain.google.com/path/sub/path")).isTrue();
  }

  @Test
  public void isIsScope_withNonEmptyScopePath_doesNotMatchOtherDomains() {
    Scope scope = Scope.newBuilder().setDomain("google.com").setPath("/path").build();

    assertThat(ScopeUtils.isInScope(scope, "http://nongoogle.com")).isFalse();
    assertThat(ScopeUtils.isInScope(scope, "http://nongoogle.com/")).isFalse();
    assertThat(ScopeUtils.isInScope(scope, "http://nongoogle.com/path")).isFalse();
    assertThat(ScopeUtils.isInScope(scope, "http://nongoogle.com/path/")).isFalse();
    assertThat(ScopeUtils.isInScope(scope, "http://subdomain.nongoogle.com/path/sub/path"))
        .isFalse();
  }

  @Test
  public void isIsScope_withTrailingSlashScopePath_matchesPathAndSubPathsOnSameDomain() {
    Scope scope = Scope.newBuilder().setDomain("google.com").setPath("/path/").build();

    assertThat(ScopeUtils.isInScope(scope, "http://google.com")).isFalse();
    assertThat(ScopeUtils.isInScope(scope, "http://google.com/")).isFalse();
    assertThat(ScopeUtils.isInScope(scope, "http://google.com/path")).isTrue();
    assertThat(ScopeUtils.isInScope(scope, "http://google.com/path/")).isTrue();
    assertThat(ScopeUtils.isInScope(scope, "http://subdomain.google.com/path/sub/path")).isTrue();
  }

  @Test
  public void isIsScope_withTrailingSlashScopePath_doesNotMatchOtherDomains() {
    Scope scope = Scope.newBuilder().setDomain("google.com").setPath("/path/").build();

    assertThat(ScopeUtils.isInScope(scope, "http://nongoogle.com")).isFalse();
    assertThat(ScopeUtils.isInScope(scope, "http://nongoogle.com/")).isFalse();
    assertThat(ScopeUtils.isInScope(scope, "http://nongoogle.com/path")).isFalse();
    assertThat(ScopeUtils.isInScope(scope, "http://nongoogle.com/path/")).isFalse();
    assertThat(ScopeUtils.isInScope(scope, "http://subdomain.nongoogle.com/path/sub/path"))
        .isFalse();
  }

  @Test
  public void isIsScope_withUnknownPort_matchesOnlyTheSamePortOnSameDomain() {
    Scope scope = Scope.newBuilder().setDomain("google.com:8080").setPath("/path").build();

    assertThat(ScopeUtils.isInScope(scope, "http://google.com/path")).isFalse();
    assertThat(ScopeUtils.isInScope(scope, "http://google.com/path/")).isFalse();
    assertThat(ScopeUtils.isInScope(scope, "http://subdomain.google.com/path/sub/path")).isFalse();
    assertThat(ScopeUtils.isInScope(scope, "http://google.com:8080/path")).isTrue();
    assertThat(ScopeUtils.isInScope(scope, "http://google.com:8080/path/")).isTrue();
    assertThat(ScopeUtils.isInScope(scope, "http://subdomain.google.com:8080/path/sub/path"))
        .isTrue();
  }

  @Test
  public void isIsScope_withUnknownPort_doesNotMatchOtherDomains() {
    Scope scope = Scope.newBuilder().setDomain("google.com:8080").setPath("/path/").build();

    assertThat(ScopeUtils.isInScope(scope, "http://nongoogle.com:8080")).isFalse();
    assertThat(ScopeUtils.isInScope(scope, "http://nongoogle.com:8080/")).isFalse();
    assertThat(ScopeUtils.isInScope(scope, "http://nongoogle.com:8080/path")).isFalse();
    assertThat(ScopeUtils.isInScope(scope, "http://nongoogle.com:8080/path/")).isFalse();
    assertThat(ScopeUtils.isInScope(scope, "http://subdomain.nongoogle.com:8080/path/sub/path"))
        .isFalse();
  }

  @Test
  public void fromUrl_withInvalidUrl_throwsIllegalArgumentException() {
    assertThrows(IllegalArgumentException.class, () -> ScopeUtils.fromUrl("invalid_url"));
  }

  @Test
  public void fromUrl_withKnownSchemeAndPort_ignoresPortInDomain() {
    assertThat(ScopeUtils.fromUrl("http://www.google.com"))
        .isEqualTo(Scope.newBuilder().setDomain("www.google.com").setPath("").build());
    assertThat(ScopeUtils.fromUrl("http://www.google.com:80"))
        .isEqualTo(Scope.newBuilder().setDomain("www.google.com").setPath("").build());
    assertThat(ScopeUtils.fromUrl("https://www.google.com"))
        .isEqualTo(Scope.newBuilder().setDomain("www.google.com").setPath("").build());
    assertThat(ScopeUtils.fromUrl("https://www.google.com:443"))
        .isEqualTo(Scope.newBuilder().setDomain("www.google.com").setPath("").build());
  }

  @Test
  public void fromUrl_withExplicitUnknownPort_includesPortInDomain() {
    assertThat(ScopeUtils.fromUrl("http://www.google.com:8080"))
        .isEqualTo(Scope.newBuilder().setDomain("www.google.com:8080").setPath("").build());
    assertThat(ScopeUtils.fromUrl("https://www.google.com:8443"))
        .isEqualTo(Scope.newBuilder().setDomain("www.google.com:8443").setPath("").build());
  }

  @Test
  public void fromUrl_withNoPathUrl_returnsScopeWithoutPath() {
    assertThat(ScopeUtils.fromUrl("http://www.google.com"))
        .isEqualTo(Scope.newBuilder().setDomain("www.google.com").setPath("").build());
    assertThat(ScopeUtils.fromUrl("http://www.google.com/"))
        .isEqualTo(Scope.newBuilder().setDomain("www.google.com").setPath("").build());
  }

  @Test
  public void fromUrl_withPathEndsWithSlash_removesEndingSlashInPath() {
    assertThat(ScopeUtils.fromUrl("http://www.google.com/path/"))
        .isEqualTo(Scope.newBuilder().setDomain("www.google.com").setPath("/path").build());
    assertThat(ScopeUtils.fromUrl("http://www.google.com/a/long/path/"))
        .isEqualTo(Scope.newBuilder().setDomain("www.google.com").setPath("/a/long/path").build());
  }

  @Test
  public void fromUrl_withLongPathNoEndingSlash_dropsLastPathSegment() {
    assertThat(ScopeUtils.fromUrl("http://www.google.com/a/long/path"))
        .isEqualTo(Scope.newBuilder().setDomain("www.google.com").setPath("/a/long").build());
  }

  @Test
  public void fromUrl_withFilenamePath_dropsFilename() {
    assertThat(ScopeUtils.fromUrl("http://www.google.com/index.html"))
        .isEqualTo(Scope.newBuilder().setDomain("www.google.com").setPath("").build());
    assertThat(ScopeUtils.fromUrl("http://www.google.com/a/b/c/index.html"))
        .isEqualTo(Scope.newBuilder().setDomain("www.google.com").setPath("/a/b/c").build());
  }
}
