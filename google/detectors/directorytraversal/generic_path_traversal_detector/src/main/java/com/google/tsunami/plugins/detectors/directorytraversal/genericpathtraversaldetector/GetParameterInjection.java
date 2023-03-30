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
import com.google.tsunami.common.net.FuzzingUtils;
import com.google.tsunami.common.net.http.HttpRequest;
import com.google.tsunami.proto.NetworkService;
import java.net.URI;
import java.util.Optional;

/** An {@code InjectionPoint} that injects payloads as GET parameters. */
final class GetParameterInjection implements InjectionPoint {

  @Override
  public ImmutableList<PotentialExploit> injectPayload(
      NetworkService networkService, HttpRequest request, String payload) {
    ImmutableList.Builder<PotentialExploit> builder = ImmutableList.builder();
    for (HttpRequest target : FuzzingUtils.fuzzGetParametersExpectingPathValues(request, payload)) {
      Optional<FuzzingUtils.HttpQueryParameter> fuzzedParameter =
          determineFuzzedParameter(target, payload);
      if (fuzzedParameter.isPresent()) {
        builder.add(
            PotentialExploit.create(
                networkService,
                target,
                fuzzedParameter.get().value(),
                determinePriority(request, fuzzedParameter.get())));
      }
    }
    return builder.build();
  }

  private Optional<FuzzingUtils.HttpQueryParameter> determineFuzzedParameter(
      HttpRequest request, String payload) {
    ImmutableList<FuzzingUtils.HttpQueryParameter> fuzzedQuery =
        FuzzingUtils.parseQuery(URI.create(request.url()).getRawQuery());
    return fuzzedQuery.stream()
        .filter(parameter -> parameter.value().contains(payload))
        .findFirst();
  }

  private PotentialExploit.Priority determinePriority(
      HttpRequest request, FuzzingUtils.HttpQueryParameter fuzzedParameter) {
    ImmutableList<FuzzingUtils.HttpQueryParameter> originalQuery =
        FuzzingUtils.parseQuery(URI.create(request.url()).getRawQuery());
    String parameterName = fuzzedParameter.name();
    if (isPromisingParameterName(parameterName)
        || isPromisingParameterValue(originalQuery, parameterName)) {
      return PotentialExploit.Priority.HIGH;
    }

    return PotentialExploit.Priority.LOW;
  }

  private boolean isPromisingParameterName(String name) {
    return InjectionPointConstants.PROMISING_PARAMETER_NAMES.contains(normalizeParameterName(name));
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
    return InjectionPointConstants.FILE_EXTENSION_PATTERN.matcher(value).find();
  }

  private boolean isParameterValuePathLike(String value) {
    return value.contains("/") || Ascii.toLowerCase(value).contains("%2f");
  }
}
