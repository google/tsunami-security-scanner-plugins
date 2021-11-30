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
import static com.google.common.net.HttpHeaders.LOCATION;
import static java.util.concurrent.TimeUnit.SECONDS;

import com.google.tsunami.common.net.http.HttpStatus;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.RecordedRequest;

/**
 * A testing dispatcher that fakes a web server with the following endpoints:
 *
 * <ul>
 *   <li>"/redirect" always redirects to "/".
 *   <li>"/" always serves the given HTML response.
 *   <li>"/anchor-link" always serves response "anchor-link-response".
 *   <li>"/img-src" always serves response "img-src-response".
 *   <li>"/timeout" always serves response after 20 seconds.
 * </ul>
 */
final class FakeServerDispatcher extends Dispatcher {
  private final String rootPageBody;

  FakeServerDispatcher(String rootPageBody) {
    this.rootPageBody = checkNotNull(rootPageBody);
  }

  @Override
  public MockResponse dispatch(RecordedRequest request) {
    switch (request.getPath()) {
      case "/redirect":
        return new MockResponse().setResponseCode(HttpStatus.FOUND.code()).setHeader(LOCATION, "/");
      case "/":
        return new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody(rootPageBody);
      case "/anchor-link":
        return new MockResponse()
            .setResponseCode(HttpStatus.OK.code())
            .setBody("anchor-link-response");
      case "/img-src":
        return new MockResponse().setResponseCode(HttpStatus.OK.code()).setBody("img-src-response");
      case "/timeout":
        return new MockResponse()
            .setResponseCode(HttpStatus.OK.code())
            .setBody("timeout-response")
            .setBodyDelay(20, SECONDS);
      default: // fall out
    }
    return new MockResponse().setResponseCode(404);
  }
}
