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
package com.google.tsunami.plugins.detectors.rce.tomcat.ghostcat.ajp;

import static com.google.common.truth.Truth.assertThat;

import java.io.IOException;
import java.nio.charset.Charset;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link GhostcatAjpForwardRequest}. */
@RunWith(JUnit4.class)
public final class GhostcatAjpForwardRequestTest {
  @Test
  public void encodeRequest_always_encodesCorrectly() throws IOException {
    byte[] request = GhostcatAjpForwardRequest.encodeRequest(
        "localhost", 8009, "/manager/xxxxx.jsp", "/WEB-INF/web.xml");

    String requestString = new String(request, Charset.defaultCharset());
    assertThat(requestString).contains("localhost");
    assertThat(requestString).contains("/manager/xxxxx.jsp");
    assertThat(requestString).contains("/WEB-INF/web.xml");
    assertThat(request[0]).isEqualTo((byte) 0x02); // JK_AJP13_FORWARD_REQUEST_PREFIX
    assertThat(request[request.length - 1]).isEqualTo((byte) 0xff); // REQUEST_TERMINATOR
  }
}
