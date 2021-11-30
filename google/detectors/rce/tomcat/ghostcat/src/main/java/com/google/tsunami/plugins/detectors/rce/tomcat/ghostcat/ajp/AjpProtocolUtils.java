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

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableMultimap;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.util.Map;
import java.util.Optional;

/**
 * A set of Ajp protocol utilities used to encode common data according to the AJPv13 AJP Protocol
 * Reference.
 *
 * @see <a href="https://tomcat.apache.org/connectors-doc/ajp/ajpv13a.html">Protocol reference</a>
 */
final class AjpProtocolUtils {
  private static final int CONTAINER_TO_SERVER_MAGIC = ('A' << 8) | 'B';
  private static final int SERVER_TO_CONTAINER_MAGIC = 0x1234;
  private static final byte REQ_ATTRIBUTE_TYPE = 0x0a;

  private static final ImmutableMap<String, Integer> COMMON_REQUEST_HEADER_NAMES =
      ImmutableMap.<String, Integer>builder()
          .put("accept", 0xA001)
          .put("accept-charset", 0xA002)
          .put("accept-encoding", 0xA003)
          .put("accept-language", 0xA004)
          .put("authorization", 0xA005)
          .put("connection", 0xA006)
          .put("content-type", 0xA007)
          .put("content-length", 0xA008)
          .put("cookie", 0xA009)
          .put("cookie2", 0xA00A)
          .put("host", 0xA00B)
          .put("pragma", 0xA00C)
          .put("referer", 0xA00D)
          .put("user-agent", 0xA00E)
          .build();
  private static final ImmutableMap<Integer, String> COMMON_RESPONSE_HEADER_CODES =
      ImmutableMap.<Integer, String>builder()
          .put(0xA001, "Content-Type")
          .put(0xA002, "Content-Language")
          .put(0xA003, "Content-Length")
          .put(0xA004, "Date")
          .put(0xA005, "Last-Modified")
          .put(0xA006, "Location")
          .put(0xA007, "Set-Cookie")
          .put(0xA008, "Set-Cookie2")
          .put(0xA009, "Servlet-Engine")
          .put(0xA00A, "Status")
          .put(0xA00B, "WWW-Authenticate")
          .build();

  /**
   * Decodes from the given {@link DataInputStream} a basic AJP packet that came from the Container
   * to Server.
   */
  static byte[] decodePacket(DataInputStream dataInputStream) throws IOException {
    int magic = dataInputStream.readUnsignedShort(); // magic
    if (magic != CONTAINER_TO_SERVER_MAGIC) {
      throw new IOException("Invalid magic.");
    }

    int length = dataInputStream.readUnsignedShort(); // data length
    byte[] data = new byte[length];
    int bytesRead = dataInputStream.read(data, 0, length); // data
    if (bytesRead != length) {
      throw new IOException(
          String.format("Invalid data length. Read %d bytes and expected %d.", bytesRead, length));
    }
    return data;
  }

  /**
   * Encodes the provided data into a basic AJP packet that is meant to go from Server to Container.
   */
  static byte[] encodePacket(byte[] data) throws IOException {
    ByteArrayOutputStream byteOutputStream = new ByteArrayOutputStream();
    try (DataOutputStream dataOutputStream = new DataOutputStream(byteOutputStream)) {
      dataOutputStream.writeShort(SERVER_TO_CONTAINER_MAGIC); // magic
      dataOutputStream.writeShort(data.length); // data length
      dataOutputStream.write(data); // data
    }
    return byteOutputStream.toByteArray();
  }

  static void encodeString(DataOutputStream dataOutputStream, String string) throws IOException {
    if (string == null) {
      dataOutputStream.writeShort(0xffff);
    } else {
      dataOutputStream.writeShort(string.length());
      dataOutputStream.write(string.getBytes(Charset.defaultCharset()));
      dataOutputStream.writeByte(0);
    }
  }

  static String decodeString(DataInputStream dataInputStream) throws IOException {
    return decodeString(dataInputStream, Optional.empty());
  }

  static String decodeString(DataInputStream dataInputStream, int length) throws IOException {
    return decodeString(dataInputStream, Optional.of(length));
  }

  private static String decodeString(
      DataInputStream dataInputStream, Optional<Integer> optionalLength) throws IOException {
    int length =
        optionalLength.isPresent() ? optionalLength.get() : dataInputStream.readUnsignedShort();
    if (length == 0xffff) {
      return null;
    }
    byte[] stringData = new byte[length];
    int read = dataInputStream.read(stringData, 0, length);
    if (read != length) {
      throw new IOException(
          String.format("Invalid string length. Read %d bytes and expected %d.", read, length));
    }
    if (dataInputStream.readByte() != 0) {
      throw new IOException("Expected null byte in the end of the string.");
    }
    return new String(stringData, Charset.defaultCharset());
  }

  static void encodeRequestAttributeAttribute(
      DataOutputStream dataOutputStream, String name, String value) throws IOException {
    dataOutputStream.writeByte(REQ_ATTRIBUTE_TYPE);
    encodeString(dataOutputStream, name);
    encodeString(dataOutputStream, value);
  }

  static void encodeRequestHeaders(
      DataOutputStream dataOutputStream, ImmutableMap<String, String> headers) throws IOException {
    dataOutputStream.writeShort(headers.size());
    for (Map.Entry<String, String> header : headers.entrySet()) {
      String name = header.getKey();
      String value = header.getValue();
      // Encode name
      if (COMMON_REQUEST_HEADER_NAMES.containsKey(name)) {
        dataOutputStream.writeShort(COMMON_REQUEST_HEADER_NAMES.get(name));
      } else {
        AjpProtocolUtils.encodeString(dataOutputStream, name);
      }
      // Encode value
      AjpProtocolUtils.encodeString(dataOutputStream, value);
    }
  }

  static ImmutableMultimap<String, String> decodeResponseHeaders(DataInputStream dataInputStream)
      throws IOException {
    ImmutableMultimap.Builder<String, String> builder = ImmutableMultimap.builder();
    int headersCount = dataInputStream.readUnsignedShort();
    for (int i = 0; i < headersCount; i++) {
      // Parse the name
      String name;
      int length = dataInputStream.readUnsignedShort();
      if (COMMON_RESPONSE_HEADER_CODES.containsKey(length)) {
        name = COMMON_RESPONSE_HEADER_CODES.get(length);
      } else {
        name = AjpProtocolUtils.decodeString(dataInputStream, length);
      }
      // Parse value
      String value = AjpProtocolUtils.decodeString(dataInputStream);
      builder.put(name, value);
    }
    return builder.build();
  }

  private AjpProtocolUtils() {}
}
