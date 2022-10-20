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

import com.google.common.base.Ascii;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.tsunami.common.net.FuzzingUtils;
import com.google.tsunami.common.net.http.HttpRequest;
import com.google.tsunami.proto.NetworkService;
import java.net.URI;
import java.util.Optional;
import java.util.regex.Pattern;

/** An {@code InjectionPoint} that injects payloads as GET parameters. */
final class GetParameterInjection implements InjectionPoint {
  private static final ImmutableSet<String> PROMISING_NAMES =
      ImmutableSet.of(
          // go/keep-sorted start
          "file", "filename", "filepath", "path", "url"
          // go/keep-sorted end
          );
  private static final Pattern FILE_EXTENSION_PATTERN = Pattern.compile(".+\\..+");

  @Override
  public ImmutableSet<PotentialExploit> injectPayload(
      NetworkService networkService, HttpRequest request, String payload) {
    ImmutableList<FuzzingUtils.HttpQueryParameter> parsedQuery =
        FuzzingUtils.parseQuery(URI.create(request.url()).getQuery());
    ImmutableSet.Builder<PotentialExploit> builder = ImmutableSet.builder();
    for (HttpRequest target : FuzzingUtils.fuzzGetParameters(request, payload)) {
      builder.add(
          PotentialExploit.create(
              networkService, target, payload, determinePriority(parsedQuery, target, payload)));
    }
    return builder.build();
  }

  private PotentialExploit.Priority determinePriority(
      ImmutableList<FuzzingUtils.HttpQueryParameter> originalQuery,
      HttpRequest request,
      String payload) {
    ImmutableList<FuzzingUtils.HttpQueryParameter> fuzzedQuery =
        FuzzingUtils.parseQuery(URI.create(request.url()).getQuery());

    Optional<FuzzingUtils.HttpQueryParameter> fuzzedParameter =
        fuzzedQuery.stream().filter(parameter -> parameter.value().equals(payload)).findFirst();
    if (fuzzedParameter.isPresent()) {
      String parameterName = fuzzedParameter.get().name();
      if (isPromisingParameterName(parameterName)
          || isPromisingParameterValue(originalQuery, parameterName)) {
        return PotentialExploit.Priority.HIGH;
      }
    }

    return PotentialExploit.Priority.LOW;
  }

  private boolean isPromisingParameterName(String name) {
    return PROMISING_NAMES.contains(normalizeParameterName(name));
  }

  private String normalizeParameterName(String name) {
    return Ascii.toLowerCase(name).replace("-", "").replace("_", "");
  }

  private boolean isPromisingParameterValue(
      ImmutableList<FuzzingUtils.HttpQueryParameter> query, String name) {
    String originalParameterValue =
        query.stream().filter(parameter -> parameter.name().equals(name)).findFirst().get().value();

    return isParameterValueExtensionLike(originalParameterValue)
        || isParameterValuePathLike(originalParameterValue);
  }

  private boolean isParameterValueExtensionLike(String value) {
    return FILE_EXTENSION_PATTERN.matcher(value).find();
  }

  private boolean isParameterValuePathLike(String value) {
    return value.contains("/");
  }
}
