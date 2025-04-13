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

import static com.google.common.net.HttpHeaders.CONTENT_LENGTH;
import static com.google.common.net.HttpHeaders.CONTENT_TYPE;
import static com.google.common.net.HttpHeaders.HOST;
import static com.google.common.net.MediaType.PLAIN_TEXT_UTF_8;
import static com.google.common.truth.Truth.assertThat;
import static com.google.tsunami.common.net.http.HttpRequest.get;
import static com.google.tsunami.common.net.http.HttpRequest.post;
import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.common.io.Resources;
import com.google.protobuf.ByteString;
import com.google.tsunami.common.net.http.HttpHeaders;
import com.google.tsunami.common.net.http.HttpRequest;
import com.google.tsunami.common.net.http.HttpResponse;
import com.google.tsunami.common.net.http.HttpStatus;
import java.io.IOException;
import okhttp3.HttpUrl;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class CheckTracesTest {
  private static final HttpRequest POST_REQUEST =
      post("http://localhost:8080/test")
          .setHeaders(
              HttpHeaders.builder()
                  .addHeader(HOST, "localhost:8080")
                  .addHeader(CONTENT_TYPE, PLAIN_TEXT_UTF_8.toString())
                  .build())
          .setRequestBody(ByteString.copyFromUtf8("request_body"))
          .build();
  private static final HttpResponse POST_RESPONSE =
      HttpResponse.builder()
          .setStatus(HttpStatus.OK)
          .setResponseUrl(HttpUrl.get(POST_REQUEST.url()))
          .setHeaders(HttpHeaders.builder().addHeader(CONTENT_LENGTH, "13").build())
          .setBodyBytes(ByteString.copyFromUtf8("response_body"))
          .build();
  private static final HttpRequest GET_REQUEST =
      get("http://localhost:8080/test?query=1#frag=2")
          .setHeaders(HttpHeaders.builder().addHeader(HOST, "localhost:8080").build())
          .build();
  private static final HttpResponse GET_RESPONSE =
      HttpResponse.builder()
          .setStatus(HttpStatus.NOT_FOUND)
          .setResponseUrl(HttpUrl.get(GET_REQUEST.url()))
          .setHeaders(HttpHeaders.builder().addHeader(CONTENT_LENGTH, "9").build())
          .setBodyBytes(ByteString.copyFromUtf8("not_found"))
          .build();

  @Test
  public void dump_whenNoTraces_returnsEmptyString() {
    var checkTraces = CheckTraces.builder().build();

    assertThat(checkTraces.dump()).isEmpty();
  }

  @Test
  public void dump_whenSingleTrace_returnsValidString() throws IOException {
    var checkTraces = CheckTraces.builder().add(POST_REQUEST, POST_RESPONSE).build();

    assertThat(checkTraces.dump())
        .isEqualTo(
            Resources.toString(
                    Resources.getResource(this.getClass(), "check_traces_single_request.txt"),
                    UTF_8)
                .strip());
  }

  @Test
  public void dump_whenMultipleTraces_returnsValidString() throws IOException {
    var checkTraces =
        CheckTraces.builder()
            .add(GET_REQUEST, GET_RESPONSE)
            .add(POST_REQUEST, POST_RESPONSE)
            .build();

    assertThat(checkTraces.dump())
        .isEqualTo(
            Resources.toString(
                    Resources.getResource(this.getClass(), "check_traces_mult_requests.txt"), UTF_8)
                .strip());
  }
}
