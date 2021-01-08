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

import static com.google.common.base.Preconditions.checkArgument;

import com.google.common.base.CharMatcher;
import com.google.common.base.Joiner;
import com.google.common.base.Splitter;
import com.google.common.base.Strings;
import com.google.common.collect.Iterables;
import com.google.tsunami.proto.CrawlConfig.Scope;
import java.util.List;
import java.util.OptionalInt;
import java.util.regex.Pattern;
import okhttp3.HttpUrl;

/** Static utility methods pertaining to {@link Scope} proto buffer. */
public final class ScopeUtils {
  private static final Pattern ENDING_SLASHES_PATTERN = Pattern.compile("/+$");
  private static final Joiner PATH_JOINER = Joiner.on('/');

  private ScopeUtils() {}

  /**
   * Checks if the given {@code url} is within the {@code scope}. Subpaths and subdomains are
   * accepted. Port comparison is only enforced if the scope port is present.
   */
  public static boolean isInScope(Scope scope, String url) {
    checkArgument(!Strings.isNullOrEmpty(url), "Url cannot be empty.");

    return isInScope(scope, fromUrl(url));
  }

  /**
   * Checks if the given {@code other} Scope is within the {@code scope}. Subpaths and subdomains
   * are accepted. Port comparison is only enforced if the scope port is present.
   */
  public static boolean isInScope(Scope scope, Scope other) {
    scope = normalize(scope);
    other = normalize(other);

    String scopeHost = getHost(scope.getDomain());
    String otherHost = getHost(other.getDomain());
    OptionalInt scopePort = getPort(scope.getDomain());
    OptionalInt otherPort = getPort(other.getDomain());
    String scopePath = scope.getPath();
    String otherPath = other.getPath();

    // Accept sub-paths and subdomains. Port comparison is only enforced hen the scope port is
    // present.
    return (otherHost.equals(scopeHost) || otherHost.endsWith("." + scopeHost))
        && (otherPath.equals(scopePath) || otherPath.startsWith(scopePath + "/"))
        && (!scopePort.isPresent() || scopePort.getAsInt() == otherPort.orElse(-1));
  }

  /** Builds a {@link Scope} protobuf from the given {@code url}. */
  public static Scope fromUrl(String url) {
    HttpUrl httpUrl = HttpUrl.parse(url);
    if (httpUrl == null) {
      throw new IllegalArgumentException(String.format("Input url '%s' cannot be parsed.", url));
    }

    String domain = buildScopeDomain(httpUrl);
    List<String> pathSegments = httpUrl.pathSegments();

    // If path ends with "/", build Scope directly from path.
    if (Iterables.getLast(pathSegments).isEmpty()) {
      return normalize(
          Scope.newBuilder()
              .setDomain(domain)
              .setPath(buildPathFromSegments(pathSegments))
              .build());
    }

    // If the URL has more than one path segment, drop the last segment, e.g. /path/last -> /path.
    if (pathSegments.size() > 1) {
      pathSegments = pathSegments.subList(0, pathSegments.size() - 1);
    }

    // Drop the last segment if it is a filename, e.g. /path/index.html -> /path.
    String lastPath = Iterables.getLast(pathSegments);
    if (lastPath.contains(".")) {
      List<String> segments = Splitter.on('.').splitToList(lastPath);
      // Heuristic check on whether the last segment is a filename.
      if (!segments.get(0).isEmpty() && segments.get(1).length() < 5) {
        pathSegments = pathSegments.subList(0, pathSegments.size() - 1);
      }
    }

    return normalize(
        Scope.newBuilder().setDomain(domain).setPath(buildPathFromSegments(pathSegments)).build());
  }

  private static Scope normalize(Scope scope) {
    // Remove trailing slashes in domain and path.
    return Scope.newBuilder()
        .setDomain(ENDING_SLASHES_PATTERN.matcher(scope.getDomain()).replaceAll(""))
        .setPath(ENDING_SLASHES_PATTERN.matcher(scope.getPath()).replaceAll(""))
        .build();
  }

  private static String buildPathFromSegments(List<String> segments) {
    return "/" + PATH_JOINER.join(segments);
  }

  private static String buildScopeDomain(HttpUrl url) {
    StringBuilder scopeDomainBuilder = new StringBuilder(url.host());
    if (url.isHttps() ? url.port() == 443 : url.port() == 80) {
      // Ignores well known ports.
      return scopeDomainBuilder.toString();
    }
    return scopeDomainBuilder.append(":").append(url.port()).toString();
  }

  private static String getHost(String domain) {
    return (CharMatcher.is(':').countIn(domain) == 1)
        ? Splitter.on(':').splitToList(domain).get(0)
        : domain;
  }

  private static OptionalInt getPort(String domain) {
    if (CharMatcher.is(':').countIn(domain) == 1) {
      try {
        return OptionalInt.of(Integer.parseInt(Splitter.on(':').splitToList(domain).get(1)));
      } catch (NumberFormatException e) {
        return OptionalInt.empty();
      }
    }
    return OptionalInt.empty();
  }
}
