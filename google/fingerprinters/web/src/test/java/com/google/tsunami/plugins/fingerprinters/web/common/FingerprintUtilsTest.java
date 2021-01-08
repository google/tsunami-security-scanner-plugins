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

import static com.google.common.net.MediaType.HTML_UTF_8;
import static com.google.common.net.MediaType.PLAIN_TEXT_UTF_8;
import static com.google.common.truth.extensions.proto.ProtoTruth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.protobuf.ByteString;
import com.google.tsunami.plugins.fingerprinters.web.proto.Hash;
import com.google.tsunami.proto.CrawlResult;
import com.google.tsunami.proto.CrawlTarget;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for {@link FingerprintUtils}. */
@RunWith(JUnit4.class)
public final class FingerprintUtilsTest {
  private static final CrawlResult CRAWL_RESULT =
      CrawlResult.newBuilder()
          .setCrawlTarget(CrawlTarget.newBuilder().setUrl("/test").setHttpMethod("GET"))
          .setCrawlDepth(1)
          .setResponseCode(200)
          .setContentType(PLAIN_TEXT_UTF_8.toString())
          .setContent(ByteString.copyFromUtf8("test content"))
          .build();

  @Test
  public void hashCrawlResult_withKnownInput_generatesKnownOutputHashes() {
    assertThat(FingerprintUtils.hashCrawlResult(CRAWL_RESULT))
        .isEqualTo(Hash.newBuilder().setHexString("37b215983790a4c0aa401d82f3036ac8").build());
  }

  @Test
  public void hashCrawlResult_withSameContentDifferentContentType_generatesDifferentHashes() {
    CrawlResult crawlResultDifferentContentType =
        CRAWL_RESULT.toBuilder().setContentType(HTML_UTF_8.toString()).build();

    assertThat(FingerprintUtils.hashCrawlResult(crawlResultDifferentContentType))
        .isEqualTo(Hash.newBuilder().setHexString("a8c260365765e836c771a15660f889e7").build());
    assertThat(FingerprintUtils.hashCrawlResult(CRAWL_RESULT))
        .isEqualTo(Hash.newBuilder().setHexString("37b215983790a4c0aa401d82f3036ac8").build());
  }

  @Test
  public void hashCrawlResult_withDifferentCrawlDepth_generatesSameHashes() {
    assertThat(
            FingerprintUtils.hashCrawlResult(
                CRAWL_RESULT.toBuilder().setCrawlDepth(CRAWL_RESULT.getCrawlDepth() + 1).build()))
        .isEqualTo(Hash.newBuilder().setHexString("37b215983790a4c0aa401d82f3036ac8").build());
    assertThat(FingerprintUtils.hashCrawlResult(CRAWL_RESULT))
        .isEqualTo(Hash.newBuilder().setHexString("37b215983790a4c0aa401d82f3036ac8").build());
  }

  @Test
  public void hashBlob_withKnownInputs_generatesKnownOutputHashes() {
    assertThat(
            FingerprintUtils.hashBlob(
                "The quick brown fox jumps over the lazy dog".getBytes(UTF_8)))
        .isEqualTo(Hash.newBuilder().setHexString("6c1b07bc7bbc4be347939ac4a93c437a").build());
    assertThat(FingerprintUtils.hashBlob("Tsunami Security Scanner".getBytes(UTF_8)))
        .isEqualTo(Hash.newBuilder().setHexString("b09ddb503d90420d309e6f1e4c5f93c5").build());
  }
}
