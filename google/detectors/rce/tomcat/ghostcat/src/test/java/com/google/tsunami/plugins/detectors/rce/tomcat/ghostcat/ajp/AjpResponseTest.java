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
import static org.junit.Assert.assertThrows;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link AjpResponse}. */
@RunWith(JUnit4.class)
public final class AjpResponseTest {
  private static final byte[] VALID_SEND_HEADERS = {
      // AJP13_SEND_HEADERS (4)
      'A', 'B', // magic
      0, 35, // size
      4, // packet prefix
      0, -56, // status code (200 in unsigned)
      0, 3, '2', '0', '0', 0, // status message
      0, 2, // num headers
      -96 /* 0xA0 */, 0x03, 0, 3, '1', '0', '0', 0, // Content-Length: 100 (common header 0xA008)
      0, 6, 'c', 'u', 's', 't', 'o', 'm', 0, 0, 4, 't', 'e', 's', 't', 0, // custom: test
  };

  private static final byte[] VALID_SEND_BODY_CHUNK = {
      // AJP13_SEND_BODY_CHUNK (3)
      'A', 'B', // magic
      0, 13, // size
      3, // prefix
      0, 10, // chunk length
      'T', 'e', 's', 't', ' ', 'C', 'h', 'u', 'n', 'k', // chunk
  };

  private static final byte[] VALID_END_RESPONSE = {
      // AJP13_END_RESPONSE (5)
      'A', 'B', // magic
      0, 2, // size
      5, // packet prefix
      1, // reuse
  };

  private static final byte[] VALID_GET_BODY_CHUNK = {
      // AJP13_GET_BODY_CHUNK (6)
      'A', 'B', // magic
      0, 3, // size
      6, // prefix
      0, 10, // requested_length
  };

  private static final byte[] VALID_RESPONSE =
      concat(VALID_SEND_HEADERS, VALID_SEND_BODY_CHUNK, VALID_GET_BODY_CHUNK, VALID_END_RESPONSE);

  @Test
  public void read_whenValidResponse_decodesSuccessfully() throws IOException {
    ByteArrayInputStream inputStream = new ByteArrayInputStream(VALID_RESPONSE);

    AjpResponse response = AjpResponse.read(inputStream);

    assertThat(response.getStatusCode()).isEqualTo(200);
    assertThat(response.getStatusMessage()).isEqualTo("200");
    assertThat(response.getHeaders()).containsExactly("Content-Length", "100", "custom", "test");
    assertThat(response.getBodyAsString()).isEqualTo("Test Chunk");
    assertThat(response.isReuse()).isTrue();
  }

  @Test
  public void read_whenResponsePacketWithInvalidPrefix_throwsIO() {
    ByteArrayInputStream inputStream =
        new ByteArrayInputStream(
            new byte[] {
              'A', 'B', // magic
              0, 1, // size
              10, // invalid packet prefix
            });

    IOException exception = assertThrows(IOException.class, () -> AjpResponse.read(inputStream));

    assertThat(exception)
        .hasMessageThat()
        .contains("Invalid response packet. Unknown packet prefix 10.");
  }

  @Test
  public void read_whenSendBodyChunkWithInvalidLength_throwsIO() {
    byte[] invalidSendBodyChunk = VALID_SEND_BODY_CHUNK.clone();
    invalidSendBodyChunk[6] = 13;
    ByteArrayInputStream inputStream = new ByteArrayInputStream(invalidSendBodyChunk);

    IOException exception = assertThrows(IOException.class, () -> AjpResponse.read(inputStream));

    assertThat(exception)
        .hasMessageThat()
        .contains("Invalid chunk length. Read 10 bytes and expected 13.");
  }

  private static byte[] concat(byte[]... arrays) {
    int length = 0;
    for (byte[] array : arrays) {
      length += array.length;
    }
    int index = 0;
    byte[] result = new byte[length];
    for (byte[] array : arrays) {
      System.arraycopy(array, 0, result, index, array.length);
      index += array.length;
    }
    return result;
  }
}
