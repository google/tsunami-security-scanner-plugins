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

import static com.google.common.base.Preconditions.checkNotNull;

import com.google.protobuf.ByteString;
import com.google.tsunami.common.net.http.HttpMethod;
import com.google.tsunami.common.net.http.HttpStatus;
import com.google.tsunami.proto.CrawlConfig;
import com.google.tsunami.proto.CrawlResult;
import com.google.tsunami.proto.CrawlTarget;
import okhttp3.mockwebserver.MockWebServer;

/** A testing util for building protobuf data used in web crawling tests. */
final class TestDataBuilder {
  private final MockWebServer mockWebServer;

  private TestDataBuilder(MockWebServer mockWebServer) {
    this.mockWebServer = checkNotNull(mockWebServer);
  }

  static TestDataBuilder forMockServer(MockWebServer mockWebServer) {
    return new TestDataBuilder(mockWebServer);
  }

  CrawlConfig buildCrawlConfig() {
    return CrawlConfig.newBuilder()
        .setMaxDepth(10)
        .addScopes(ScopeUtils.fromUrl(mockWebServer.url("").toString()))
        .build();
  }

  CrawlTarget buildCrawlTargetForSeedPath(String seedUrl) {
    return CrawlTarget.newBuilder()
        .setHttpMethod(HttpMethod.GET.toString())
        .setUrl(mockWebServer.url(seedUrl).toString())
        .build();
  }

  CrawlResult buildCrawlResult(int depth, String url, String response) {
    return CrawlResult.newBuilder()
        .setCrawlTarget(
            CrawlTarget.newBuilder()
                .setUrl(mockWebServer.url(url).toString())
                .setHttpMethod(HttpMethod.GET.toString()))
        .setCrawlDepth(depth)
        .setResponseCode(HttpStatus.OK.code())
        .setContent(ByteString.copyFromUtf8(response))
        .build();
  }

  CrawlResult buildRedirectCrawlResult(int depth, String url) {
    return CrawlResult.newBuilder()
        .setCrawlTarget(
            CrawlTarget.newBuilder()
                .setUrl(mockWebServer.url(url).toString())
                .setHttpMethod(HttpMethod.GET.toString()))
        .setCrawlDepth(depth)
        .setResponseCode(HttpStatus.FOUND.code())
        .build();
  }
}
