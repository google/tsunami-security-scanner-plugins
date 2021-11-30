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

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableMultimap;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link AjpProtocolUtils}. */
@RunWith(JUnit4.class)
public final class AjpProtocolUtilsTest {
  private static final byte[] VALID_CONTAINER_TO_SERVER_BASIC_PACKET = {
    'A', 'B', 0, 5, 'C', 'H', 'U', 'N', 'K'
  };

  private static final byte[] VALID_STRING = {0, 5, 'V', 'A', 'L', 'I', 'D', 0};

  private static final byte[] NULL_STRING = {(byte) 0xff, (byte) 0xff};

  private static final byte[] EMPTY_STRING = {0, 0, 0};

  @Test
  public void decodePacket_whenValidPacket_decodesSuccessfully() throws IOException {
    ByteArrayInputStream byteArrayInputStream =
        new ByteArrayInputStream(VALID_CONTAINER_TO_SERVER_BASIC_PACKET);
    DataInputStream dataInputStream = new DataInputStream(byteArrayInputStream);

    byte[] chunkData = AjpProtocolUtils.decodePacket(dataInputStream);

    assertThat(chunkData).hasLength(5);
    assertThat(chunkData).isEqualTo(new byte[] {'C', 'H', 'U', 'N', 'K'});
  }

  @Test
  public void decodePacket_whenWrongMagic_throwsIO() {
    byte[] invalidPacket = VALID_CONTAINER_TO_SERVER_BASIC_PACKET.clone();
    invalidPacket[0] = 'C';
    ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(invalidPacket);
    DataInputStream dataInputStream = new DataInputStream(byteArrayInputStream);

    IOException exception =
        assertThrows(IOException.class, () -> AjpProtocolUtils.decodePacket(dataInputStream));

    assertThat(exception).hasMessageThat().contains("Invalid magic");
  }

  @Test
  public void decodePacket_whenWrongLength_throwsIO() {
    byte[] invalidPacket = VALID_CONTAINER_TO_SERVER_BASIC_PACKET.clone();
    invalidPacket[3] = 10;
    ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(invalidPacket);
    DataInputStream dataInputStream = new DataInputStream(byteArrayInputStream);

    IOException exception =
        assertThrows(IOException.class, () -> AjpProtocolUtils.decodePacket(dataInputStream));

    assertThat(exception)
        .hasMessageThat()
        .contains("Invalid data length. Read 5 bytes and expected 10.");
  }

  @Test
  public void encodePacket_always_encodesSuccessfully() throws IOException {
    byte[] packet = AjpProtocolUtils.encodePacket(new byte[] {'C', 'H', 'U', 'N', 'K'});

    assertThat(packet).isEqualTo(new byte[] {0x12, 0x34, 0, 5, 'C', 'H', 'U', 'N', 'K'});
  }

  @Test
  public void encodeString_whenNonEmptyString_encodesSuccessfully() throws IOException {
    ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();

    try (DataOutputStream dataOutputStream = new DataOutputStream(byteArrayOutputStream)) {
      AjpProtocolUtils.encodeString(dataOutputStream, "String");
    }

    byte[] string = byteArrayOutputStream.toByteArray();
    assertThat(string).isEqualTo(new byte[] {0, 6, 'S', 't', 'r', 'i', 'n', 'g', 0});
  }

  @Test
  public void encodeString_whenEmptyString_encodesSuccessfully() throws IOException {
    ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();

    try (DataOutputStream dataOutputStream = new DataOutputStream(byteArrayOutputStream)) {
      AjpProtocolUtils.encodeString(dataOutputStream, "");
    }

    byte[] string = byteArrayOutputStream.toByteArray();
    assertThat(string).isEqualTo(EMPTY_STRING);
  }

  @Test
  public void encodeString_whenNullString_encodesSuccessfully() throws IOException {
    ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();

    try (DataOutputStream dataOutputStream = new DataOutputStream(byteArrayOutputStream)) {
      AjpProtocolUtils.encodeString(dataOutputStream, null);
    }

    byte[] string = byteArrayOutputStream.toByteArray();
    assertThat(string).isEqualTo(NULL_STRING);
  }

  @Test
  public void decodeString_whenValidString_decodesSuccessfully() throws IOException {
    ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(VALID_STRING);
    DataInputStream dataInputStream = new DataInputStream(byteArrayInputStream);

    String string = AjpProtocolUtils.decodeString(dataInputStream);

    assertThat(string).isEqualTo("VALID");
  }

  @Test
  public void decodeString_whenNullString_decodesSuccessfully() throws IOException {
    ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(NULL_STRING);
    DataInputStream dataInputStream = new DataInputStream(byteArrayInputStream);

    String string = AjpProtocolUtils.decodeString(dataInputStream);

    assertThat(string).isNull();
  }

  @Test
  public void decodeString_whenEmptyString_decodesSuccessfully() throws IOException {
    ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(EMPTY_STRING);
    DataInputStream dataInputStream = new DataInputStream(byteArrayInputStream);

    String string = AjpProtocolUtils.decodeString(dataInputStream);

    assertThat(string).isEmpty();
  }

  @Test
  public void decodeString_whenWrongLength_throwsIO() {
    byte[] invalidString = VALID_STRING.clone();
    invalidString[1] = 10;
    ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(invalidString);
    DataInputStream dataInputStream = new DataInputStream(byteArrayInputStream);

    IOException exception =
        assertThrows(IOException.class, () -> AjpProtocolUtils.decodeString(dataInputStream));

    assertThat(exception)
        .hasMessageThat()
        .contains("Invalid string length. Read 6 bytes and expected 10.");
  }

  @Test
  public void decodeString_whenNoNullByte_throwsIO() {
    byte[] invalidString = {0, 1, 'A', 1};
    ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(invalidString);
    DataInputStream dataInputStream = new DataInputStream(byteArrayInputStream);

    IOException exception =
        assertThrows(IOException.class, () -> AjpProtocolUtils.decodeString(dataInputStream));

    assertThat(exception).hasMessageThat().contains("Expected null byte in the end of the string");
  }

  @Test
  public void decodeString_whenProvidedLength_doesntRequireLengthBytesToDecodeSuccessfully()
      throws IOException {
    byte[] noLengthString = {'N', 'o', ' ', 'l', 'e', 'n', 'g', 't', 'h', 0};
    ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(noLengthString);
    DataInputStream dataInputStream = new DataInputStream(byteArrayInputStream);

    String string = AjpProtocolUtils.decodeString(dataInputStream, 9);

    assertThat(string).isEqualTo("No length");
  }

  @Test
  public void encodeRequestAttributeAttribute_always_encodesSuccessfully() throws IOException {
    ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();

    try (DataOutputStream dataOutputStream = new DataOutputStream(byteArrayOutputStream)) {
      AjpProtocolUtils.encodeRequestAttributeAttribute(dataOutputStream, "name", "value");
    }

    byte[] attribute = byteArrayOutputStream.toByteArray();
    assertThat(attribute)
        .isEqualTo(
            new byte[] {
              0x0A, // req_attribute type code
              0, 4, 'n', 'a', 'm', 'e', 0, // name string followed by value string
              0, 5, 'v', 'a', 'l', 'u', 'e', 0
            });
  }

  @Test
  public void encodeRequestHeaders_whenCommonHeader_encodesSuccessful() throws IOException {
    ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();

    try (DataOutputStream dataOutputStream = new DataOutputStream(byteArrayOutputStream)) {
      AjpProtocolUtils.encodeRequestHeaders(
          dataOutputStream, ImmutableMap.of("content-length", "100"));
    }

    byte[] headers = byteArrayOutputStream.toByteArray();
    assertThat(headers)
        .isEqualTo(
            new byte[] {
                0, 1, // num_headers
                (byte) 0xA0, 0x8, // code name followed by value string
                0, 3, '1', '0', '0', 0
            });
  }

  @Test
  public void encodeRequestHeaders_whenUncommonHeader_encodesSuccessful() throws IOException {
    ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();

    try (DataOutputStream dataOutputStream = new DataOutputStream(byteArrayOutputStream)) {
      AjpProtocolUtils.encodeRequestHeaders(dataOutputStream, ImmutableMap.of("name", "value"));
    }

    byte[] headers = byteArrayOutputStream.toByteArray();
    assertThat(headers)
        .isEqualTo(
            new byte[] {
                0, 1, // num_headers
                0, 4, 'n', 'a', 'm', 'e', 0, // name string followed by value string
                0, 5, 'v', 'a', 'l', 'u', 'e', 0
            });
  }

  @Test
  public void decodeResponseHeaders_whenCommonHeader_decodesSuccessfully() throws IOException {
    byte[] validHeaders = {
        0, 1, // num_headers
        (byte) 0xA0, 0x03, // code name followed by value string
        0, 3, '2', '0', '0', 0};
    ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(validHeaders);
    DataInputStream dataInputStream = new DataInputStream(byteArrayInputStream);

    ImmutableMultimap<String, String> headers =
        AjpProtocolUtils.decodeResponseHeaders(dataInputStream);

    assertThat(headers).containsExactly("Content-Length", "200");
  }

  @Test
  public void decodeResponseHeaders_whenUncommonHeader_decodesSuccessfully() throws IOException {
    byte[] validHeaders = {
        0, 1, // num_headers
        0, 4, 't', 'e', 's', 't', 0, // name string followed by value string
        0, 2, 'o', 'k', 0};
    ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(validHeaders);
    DataInputStream dataInputStream = new DataInputStream(byteArrayInputStream);

    ImmutableMultimap<String, String> headers =
        AjpProtocolUtils.decodeResponseHeaders(dataInputStream);

    assertThat(headers).containsExactly("test", "ok");
  }

  @Test
  public void decodeResponseHeaders_whenDuplicateHeaders_decodesSuccessfully() throws IOException {
    byte[] validHeaders = {
        0, 2, // num_headers
        (byte) 0xA0, 0x07, // code name followed by value string
        0, 4, 't', 'e', 's', 't', 0,
        (byte) 0xA0, 0x07, // code name followed by value string
        0, 6, 'c', 'o', 'o', 'k', 'i', 'e', 0};
    ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(validHeaders);
    DataInputStream dataInputStream = new DataInputStream(byteArrayInputStream);

    ImmutableMultimap<String, String> headers =
        AjpProtocolUtils.decodeResponseHeaders(dataInputStream);

    assertThat(headers).containsExactly("Set-Cookie", "test", "Set-Cookie", "cookie");
  }
}
