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

import com.google.common.collect.ImmutableSet;
import com.google.tsunami.common.net.UrlUtils;
import com.google.tsunami.common.net.http.HttpRequest;
import com.google.tsunami.proto.NetworkService;
import java.net.URI;

/**
 * An {@code InjectionPoint} that plants payloads at the root, current path, and frequently
 * encountered path prefixes of the url.
 */
final class PathParameterInjection implements InjectionPoint {
  private static final String[] commonPaths = {
    // go/keep-sorted start
    "admin",
    "album",
    "app",
    "assets",
    "bin",
    "console",
    "css",
    "demo",
    "doc",
    "eqx",
    "files",
    "fs",
    "html",
    "img-sys",
    "jquery_ui",
    "js",
    "media",
    "public",
    "scripts",
    "static",
    "tmp",
    "upload",
    "xls",
    // go/keep-sorted end
  };

  private HttpRequest buildModifiedRequest(HttpRequest request, String url) {
    return request.toBuilder().setUrl(url).build();
  }

  private String extractRoot(URI url) {
    return url.getScheme() + "://" + url.getRawAuthority();
  }

  @Override
  public ImmutableSet<PotentialExploit> injectPayload(
      NetworkService networkService, HttpRequest request, String payload) {
    ImmutableSet.Builder<PotentialExploit> builder = ImmutableSet.builder();
    for (String target : this.generateFuzzTargets(URI.create(request.url()), payload)) {
      builder.add(
          PotentialExploit.create(
              networkService,
              this.buildModifiedRequest(request, target),
              payload,
              PotentialExploit.Priority.LOW));
    }
    return builder.build();
  }

  private ImmutableSet<String> generateFuzzTargets(URI url, String payload) {
    return ImmutableSet.<String>builder()
        .addAll(this.generateTargetAtRoot(url, payload))
        .addAll(this.generateTargetAtCurrentPath(url, payload))
        .addAll(this.generateTargetAtCommonPaths(url, payload))
        .build();
  }

  private ImmutableSet<String> generateTargetAtRoot(URI url, String payload) {
    return ImmutableSet.of(this.extractRoot(url) + "/" + payload);
  }

  private ImmutableSet<String> generateTargetAtCurrentPath(URI url, String payload) {
    String path = UrlUtils.removeTrailingSlashes(url.getRawPath());
    String prefix = "";
    int endOfParent = path.lastIndexOf("/");
    if (endOfParent != -1) {
      prefix = path.substring(0, endOfParent);
    }
    return ImmutableSet.of(this.extractRoot(url) + prefix + "/" + payload);
  }

  private ImmutableSet<String> generateTargetAtCommonPaths(URI url, String payload) {
    ImmutableSet.Builder<String> builder = ImmutableSet.builder();
    for (String commonPath : commonPaths) {
      builder.add(this.extractRoot(url) + "/" + commonPath + "/" + payload);
    }
    return builder.build();
  }
}
