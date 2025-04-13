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

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.tsunami.common.net.UrlUtils;
import com.google.tsunami.common.net.http.HttpRequest;
import com.google.tsunami.proto.NetworkService;
import java.net.URI;

/**
 * An {@code InjectionPoint} that plants payloads at the root and frequently encountered path
 * prefixes of the url.
 */
final class RootInjection implements InjectionPoint {

  @Override
  public ImmutableList<PotentialExploit> injectPayload(
      NetworkService networkService, HttpRequest request, String payload) {
    ImmutableList.Builder<PotentialExploit> builder = ImmutableList.builder();
    if (isRoot(request)) {
      for (String target : this.generateFuzzTargets(extractRoot(request), payload)) {
        builder.add(
            PotentialExploit.create(
                networkService,
                this.buildModifiedRequest(request, target),
                payload,
                PotentialExploit.Priority.LOW));
      }
    }
    return builder.build();
  }

  private HttpRequest buildModifiedRequest(HttpRequest request, String url) {
    return request.toBuilder().setUrl(url).build();
  }

  private String extractRoot(HttpRequest request) {
    URI url = URI.create(request.url());
    return url.getScheme() + "://" + url.getRawAuthority();
  }

  private boolean isRoot(HttpRequest request) {
    return UrlUtils.removeTrailingSlashes(request.url()).equals(extractRoot(request));
  }

  private ImmutableSet<String> generateFuzzTargets(String root, String payload) {
    return ImmutableSet.<String>builder()
        .addAll(this.generateTargetAtRoot(root, payload))
        .addAll(this.generateTargetAtCommonPaths(root, payload))
        .build();
  }

  private ImmutableSet<String> generateTargetAtRoot(String root, String payload) {
    return ImmutableSet.of(root + "/" + payload);
  }

  private ImmutableSet<String> generateTargetAtCommonPaths(String root, String payload) {
    ImmutableSet.Builder<String> builder = ImmutableSet.builder();
    for (String commonPath : InjectionPointConstants.COMMON_PATHS) {
      builder.add(root + "/" + commonPath + "/" + payload);
    }
    return builder.build();
  }
}
