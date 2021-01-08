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
import static com.google.common.net.MediaType.HTML_UTF_8;
import static com.google.common.truth.extensions.proto.ProtoTruth.assertThat;
import static com.google.tsunami.plugins.fingerprinters.web.common.CrawlUtils.buildCrawlResult;

import com.google.protobuf.ByteString;
import com.google.tsunami.common.net.http.HttpHeaders;
import com.google.tsunami.common.net.http.HttpResponse;
import com.google.tsunami.common.net.http.HttpStatus;
import com.google.tsunami.proto.CrawlResult;
import com.google.tsunami.proto.CrawlTarget;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for {@link CrawlUtils}. */
@RunWith(JUnit4.class)
public final class CrawlUtilsTest {

  @Test
  public void buildCrawlResult_whenFullHttpResponse_returnsExpectedCrawlResult() {
    HttpResponse httpResponse =
        HttpResponse.builder()
            .setStatus(HttpStatus.OK)
            .setHeaders(
                HttpHeaders.builder().addHeader(CONTENT_TYPE, HTML_UTF_8.toString()).build())
            .setBodyBytes(ByteString.copyFromUtf8("body"))
            .build();

    assertThat(buildCrawlResult(CrawlTarget.getDefaultInstance(), 1, httpResponse))
        .isEqualTo(
            CrawlResult.newBuilder()
                .setCrawlTarget(CrawlTarget.getDefaultInstance())
                .setCrawlDepth(1)
                .setResponseCode(HttpStatus.OK.code())
                .setContentType(HTML_UTF_8.toString())
                .setContent(ByteString.copyFromUtf8("body"))
                .build());
  }

  @Test
  public void buildCrawlResult_whenNoContentType_returnsCrawlResultWithoutContentType() {
    HttpResponse httpResponse =
        HttpResponse.builder()
            .setStatus(HttpStatus.OK)
            .setHeaders(HttpHeaders.builder().build())
            .setBodyBytes(ByteString.copyFromUtf8("body"))
            .build();

    assertThat(buildCrawlResult(CrawlTarget.getDefaultInstance(), 1, httpResponse))
        .isEqualTo(
            CrawlResult.newBuilder()
                .setCrawlTarget(CrawlTarget.getDefaultInstance())
                .setCrawlDepth(1)
                .setResponseCode(HttpStatus.OK.code())
                .setContent(ByteString.copyFromUtf8("body"))
                .build());
  }

  @Test
  public void buildCrawlResult_whenNoResponseBody_returnsCrawlResultWithoutContent() {
    HttpResponse httpResponse =
        HttpResponse.builder()
            .setStatus(HttpStatus.OK)
            .setHeaders(
                HttpHeaders.builder().addHeader(CONTENT_TYPE, HTML_UTF_8.toString()).build())
            .build();

    assertThat(buildCrawlResult(CrawlTarget.getDefaultInstance(), 1, httpResponse))
        .isEqualTo(
            CrawlResult.newBuilder()
                .setCrawlTarget(CrawlTarget.getDefaultInstance())
                .setCrawlDepth(1)
                .setResponseCode(HttpStatus.OK.code())
                .setContentType(HTML_UTF_8.toString())
                .build());
  }
}
