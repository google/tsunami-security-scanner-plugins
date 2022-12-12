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
package com.google.tsunami.plugins.detectors.solr;

import static java.util.stream.Collectors.joining;

import com.google.auto.value.AutoValue;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Streams;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.google.tsunami.common.net.http.HttpHeaders;
import com.google.tsunami.common.net.http.HttpRequest;
import com.google.tsunami.common.net.http.HttpResponse;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Optional;

@AutoValue
abstract class CheckTraces {

  abstract ImmutableList<TraceEntry> entries();

  static CheckTraces.Builder builder() {
    return new AutoValue_CheckTraces.Builder();
  }

  @AutoValue.Builder
  abstract static class Builder {
    abstract ImmutableList.Builder<TraceEntry> entriesBuilder();

    @CanIgnoreReturnValue
    final CheckTraces.Builder add(HttpRequest request, HttpResponse response) {
      entriesBuilder().add(TraceEntry.create(request, response));
      return this;
    }

    abstract CheckTraces build();
  }

  final String dump() {
    return Streams.mapWithIndex(entries().stream(), TraceEntry::dump).collect(joining("\n\n"));
  }

  @AutoValue
  abstract static class TraceEntry {
    abstract HttpRequest request();

    abstract HttpResponse response();

    static CheckTraces.TraceEntry create(HttpRequest request, HttpResponse response) {
      return new AutoValue_CheckTraces_TraceEntry(request, response);
    }

    String dump(long index) {
      return dumpHttpRequest(index) + "\n\n" + dumpHttpResponse(index);
    }

    private String dumpHttpRequest(long index) {
      try {
        var uri = new URI(request().url());
        var requestBuilder = new StringBuilder();
        requestBuilder.append("- Request ").append(index + 1).append(":\n\n");
        requestBuilder
            .append(request().method())
            .append(" ")
            .append(uri.getRawPath())
            .append(uri.getRawQuery() == null ? "" : "?" + uri.getRawQuery())
            .append(uri.getRawFragment() == null ? "" : "#" + uri.getRawFragment())
            .append(" ")
            .append("HTTP/1.1");
        requestBuilder.append(dumpHttpHeaders(request().headers()));
        request()
            .requestBody()
            .flatMap(body -> body.isEmpty() ? Optional.empty() : Optional.of(body))
            .ifPresent(body -> requestBuilder.append("\n\n").append(body.toStringUtf8()));
        return requestBuilder.toString();
      } catch (URISyntaxException e) {
        throw new AssertionError(
            String.format("This should never happen. Invalid URL: %s", request().url()), e);
      }
    }

    private String dumpHttpResponse(long index) {
      var responseBuilder = new StringBuilder();
      responseBuilder.append("- Response ").append(index + 1).append(":\n\n");
      responseBuilder
          .append("HTTP/1.1 ")
          .append(response().status().code())
          .append(" ")
          .append(response().status());
      responseBuilder.append(dumpHttpHeaders(response().headers()));
      response()
          .bodyString()
          .flatMap(body -> body.isEmpty() ? Optional.empty() : Optional.of(body))
          .ifPresent(body -> responseBuilder.append("\n\n").append(body));
      return responseBuilder.toString();
    }

    private static String dumpHttpHeaders(HttpHeaders headers) {
      var dumpedHeaders =
          headers.names().stream()
              .flatMap(
                  headerName ->
                      headers.getAll(headerName).stream()
                          .map(headerValue -> headerName + ": " + headerValue))
              .collect(joining("\n"));
      return dumpedHeaders.isEmpty() ? "" : "\n" + dumpedHeaders;
    }
  }
}
