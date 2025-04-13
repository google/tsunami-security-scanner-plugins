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

import static com.google.common.truth.Truth.assertThat;

import com.google.protobuf.ByteString;
import com.google.tsunami.common.net.http.HttpHeaders;
import com.google.tsunami.common.net.http.HttpRequest;
import com.google.tsunami.common.net.http.HttpResponse;
import com.google.tsunami.common.net.http.HttpStatus;
import com.google.tsunami.proto.NetworkService;
import okhttp3.HttpUrl;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class DetectionTest {

  @Test
  public void toString_always_containsResponseBody() {
    HttpResponse response =
        HttpResponse.builder()
            .setStatus(HttpStatus.OK)
            .setHeaders(HttpHeaders.builder().build())
            .setBodyBytes(ByteString.copyFromUtf8("Hello World"))
            .setResponseUrl(HttpUrl.parse("https://google.com"))
            .build();
    PotentialExploit exploit =
        PotentialExploit.create(
            NetworkService.newBuilder().setServiceName("http").build(),
            HttpRequest.get("https://google.com").withEmptyHeaders().build(),
            "../../etc/passwd",
            PotentialExploit.Priority.HIGH);
    Detection detection = Detection.create(exploit, response);

    assertThat(detection.toString()).contains("Hello World");
  }
}
