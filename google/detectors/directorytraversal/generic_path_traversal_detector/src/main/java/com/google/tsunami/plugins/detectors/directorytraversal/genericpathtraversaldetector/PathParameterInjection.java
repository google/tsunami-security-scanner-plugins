/*
 * Copyright 2022 Google LLC
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
package com.google.tsunami.plugins.detectors.directorytraversal.genericpathtraversaldetector;

import static java.util.stream.Collectors.joining;

import com.google.auto.value.AutoValue;
import com.google.common.base.Ascii;
import com.google.common.collect.ImmutableSet;
import com.google.tsunami.common.net.UrlUtils;
import com.google.tsunami.common.net.http.HttpRequest;
import com.google.tsunami.proto.NetworkService;
import java.net.URI;
import java.util.regex.Pattern;

/** An {@code InjectionPoint} that plants payloads at the current path. */
final class PathParameterInjection implements InjectionPoint {
  private static final Pattern COMMON_PATHS_PATTERN =
      Pattern.compile(
          InjectionPointConstants.COMMON_PATHS.stream()
              .map(path -> String.format("(/%s/)", path))
              .collect(joining("|")));

  @Override
  public ImmutableSet<PotentialExploit> injectPayload(
      NetworkService networkService, HttpRequest request, String payload) {
    ImmutableSet.Builder<PotentialExploit> builder = ImmutableSet.builder();
    for (FuzzTarget fuzzTarget :
        this.generateTargetAtCurrentPath(URI.create(request.url()), payload)) {
      builder.add(
          PotentialExploit.create(
              networkService,
              this.buildModifiedRequest(request, fuzzTarget.targetUrl()),
              payload,
              fuzzTarget.priority()));
    }
    return builder.build();
  }

  private HttpRequest buildModifiedRequest(HttpRequest request, String url) {
    return request.toBuilder().setUrl(url).build();
  }

  private String extractRoot(URI url) {
    return url.getScheme() + "://" + url.getRawAuthority();
  }

  private boolean isPromisingSuffix(String suffix) {
    return Ascii.toLowerCase(suffix).contains("%2f");
  }

  private boolean endsWithFileExtension(String suffix) {
    return InjectionPointConstants.FILE_EXTENSION_PATTERN.matcher(suffix).find();
  }

  private boolean containsCommonPath(String path) {
    return COMMON_PATHS_PATTERN.matcher(path).find();
  }

  private ImmutableSet<FuzzTarget> generateTargetAtCurrentPath(URI url, String payload) {
    String path = UrlUtils.removeTrailingSlashes(url.getRawPath());
    int endOfParent = path.lastIndexOf("/");
    String prefix = endOfParent != -1 ? path.substring(0, endOfParent + 1) : "/";
    String suffix = path.substring(endOfParent + 1);
    PotentialExploit.Priority priority = PotentialExploit.Priority.LOW;
    if (isPromisingSuffix(suffix)) {
      priority = PotentialExploit.Priority.HIGH;
    } else if (endsWithFileExtension(suffix) || containsCommonPath(prefix)) {
      priority = PotentialExploit.Priority.MEDIUM;
    }
    return ImmutableSet.of(FuzzTarget.create(this.extractRoot(url) + prefix + payload, priority));
  }

  @AutoValue
  abstract static class FuzzTarget {
    abstract String targetUrl();

    abstract PotentialExploit.Priority priority();

    static FuzzTarget create(String targetUrl, PotentialExploit.Priority priority) {
      return new AutoValue_PathParameterInjection_FuzzTarget(targetUrl, priority);
    }
  }
}
