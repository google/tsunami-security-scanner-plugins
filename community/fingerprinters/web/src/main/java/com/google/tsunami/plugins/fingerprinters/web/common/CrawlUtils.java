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
package com.google.tsunami.plugins.fingerprinters.web.common;

import static com.google.common.net.HttpHeaders.CONTENT_TYPE;

import com.google.tsunami.common.net.http.HttpHeaders;
import com.google.tsunami.common.net.http.HttpResponse;
import com.google.tsunami.proto.CrawlResult;
import com.google.tsunami.proto.CrawlTarget;
import com.google.tsunami.proto.HttpHeader;
import java.util.ArrayList;
import java.util.List;

/** Utilities for crawling and crawl results. */
public final class CrawlUtils {

  public static CrawlResult buildCrawlResult(
      CrawlTarget crawlTarget, int crawlDepth, HttpResponse httpResponse) {
    CrawlResult.Builder crawlResultBuilder =
        CrawlResult.newBuilder()
            .setCrawlTarget(crawlTarget)
            .setCrawlDepth(crawlDepth)
            .setResponseCode(httpResponse.status().code());
    httpResponse.headers().get(CONTENT_TYPE).ifPresent(crawlResultBuilder::setContentType);
    httpResponse.bodyBytes().ifPresent(crawlResultBuilder::setContent);

    HttpHeaders httpResponseHeaders = httpResponse.headers();
    List<HttpHeader> httpHeaders = new ArrayList<>();
    for (String name : httpResponseHeaders.names()) {
      httpResponseHeaders
          .getAll(name)
          .forEach(
              value ->
                  httpHeaders.add(HttpHeader.newBuilder().setKey(name).setValue(value).build()));
    }
    crawlResultBuilder.addAllResponseHeaders(httpHeaders);
    return crawlResultBuilder.build();
  }

  private CrawlUtils() {}
}
