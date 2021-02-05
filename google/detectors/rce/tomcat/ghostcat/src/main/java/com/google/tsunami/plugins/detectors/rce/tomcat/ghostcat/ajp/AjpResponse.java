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

import static com.google.tsunami.plugins.detectors.rce.tomcat.ghostcat.ajp.AjpProtocolUtils.decodePacket;
import static com.google.tsunami.plugins.detectors.rce.tomcat.ghostcat.ajp.AjpProtocolUtils.decodeResponseHeaders;
import static com.google.tsunami.plugins.detectors.rce.tomcat.ghostcat.ajp.AjpProtocolUtils.decodeString;

import com.google.common.collect.ImmutableMultimap;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;

/**
 * A class that encapsulates a fully parsed AJP response. According to the AJPv13 AJP Protocol
 * Reference a response can be composed of multiple AJP response packets that will come through the
 * same connection in succession: "once a connection is assigned to a particular request, it will
 * not be used for any others until the request-handling cycle has terminated".
 *
 * @see <a href="https://tomcat.apache.org/connectors-doc/ajp/ajpv13a.html">Protocol reference</a>
 */
public class AjpResponse {
  private int statusCode = -1;
  private String statusMessage = "";
  private ImmutableMultimap<String, String> headers = ImmutableMultimap.of();
  private byte[] body = {};
  private boolean reuse = false;

  private AjpResponse() {}

  public int getStatusCode() {
    return statusCode;
  }

  public String getStatusMessage() {
    return statusMessage;
  }

  public ImmutableMultimap<String, String> getHeaders() {
    return headers;
  }

  public byte[] getBody() {
    return body;
  }

  public String getBodyAsString() {
    return new String(getBody(), Charset.defaultCharset());
  }

  public boolean isReuse() {
    return reuse;
  }

  /**
   * Processes and compiles all response packets from a request-handling cycle into an {@link
   * AjpResponse}. It keeps reading response packets until an AJP13_END_RESPONSE packet is found.
   *
   * @see <a href="https://tomcat.apache.org/connectors-doc/ajp/ajpv13a.html">Protocol reference</a>
   */
  public static AjpResponse read(InputStream inputStream) throws IOException {
    DataInputStream dataInputStream = new DataInputStream(inputStream);
    AjpResponse response = new AjpResponse();
    while (true) {
      ResponsePacket responsePacket =
          ResponsePacket.decodeResponsePacket(decodePacket(dataInputStream));
      switch (responsePacket.prefixCode) {
        case ResponsePacket.AJP13_SEND_BODY_CHUNK_PREFIX:
          {
            response.body = responsePacket.chunk;
            break;
          }
        case ResponsePacket.AJP13_SEND_HEADERS_PREFIX:
          {
            response.statusCode = responsePacket.httpStatusCode;
            response.statusMessage = responsePacket.httpStatusMessage;
            response.headers = responsePacket.headers;
            break;
          }
        case ResponsePacket.AJP13_GET_BODY_CHUNK_PREFIX:
          {
            break;
          }
        case ResponsePacket.AJP13_END_RESPONSE_PREFIX:
          {
            // Request handling cycle finished. No more packets to parse.
            response.reuse = responsePacket.reuse;
            return response;
          }
        default:
          throw new AssertionError("Impossible decoded response packet.");
      }
    }
  }

  /**
   * A class that represents an AJP Response Packet according to the AJPv13 AJP Protocol Reference.
   *
   * <p>Note: Since the contents of the response packets might differ depending on the prefix, we
   * included all data they can have in this class, kinda like a union.
   *
   * @see <a href="https://tomcat.apache.org/connectors-doc/ajp/ajpv13a.html">Protocol reference</a>
   */
  private static class ResponsePacket {
    private static final int AJP13_SEND_BODY_CHUNK_PREFIX = 3;
    private static final int AJP13_SEND_HEADERS_PREFIX = 4;
    private static final int AJP13_END_RESPONSE_PREFIX = 5;
    private static final int AJP13_GET_BODY_CHUNK_PREFIX = 6;

    private byte prefixCode;
    /* AJP13_SEND_BODY_CHUNK */
    private byte[] chunk;
    /* AJP13_SEND_HEADERS */
    private int httpStatusCode;
    private String httpStatusMessage;
    private ImmutableMultimap<String, String> headers;
    /* AJP13_END_RESPONSE */
    private boolean reuse;

    private static ResponsePacket decodeResponsePacket(byte[] data) throws IOException {
      ByteArrayInputStream byteInputStream = new ByteArrayInputStream(data);
      DataInputStream dataInputStream = new DataInputStream(byteInputStream);
      byte prefixCode = dataInputStream.readByte(); // prefix_code
      switch (prefixCode) {
        case AJP13_SEND_BODY_CHUNK_PREFIX:
          return decodeSendBodyChunk(dataInputStream);
        case AJP13_SEND_HEADERS_PREFIX:
          return decodeSendHeaders(dataInputStream);
        case AJP13_END_RESPONSE_PREFIX:
          return decodeEndResponse(dataInputStream);
        case AJP13_GET_BODY_CHUNK_PREFIX:
          return decodeGetBodyChunk();
        default:
          throw new IOException(
              String.format("Invalid response packet. Unknown packet prefix %d.", prefixCode));
      }
    }

    private static ResponsePacket decodeSendBodyChunk(DataInputStream dataInputStream)
        throws IOException {
      int chunkLength = dataInputStream.readUnsignedShort(); // chunk_length
      byte[] chunk = new byte[chunkLength];
      int bytesRead = dataInputStream.read(chunk, 0, chunkLength); // chunk
      if (bytesRead != chunkLength) {
        throw new IOException(
            String.format(
                "Invalid chunk length. Read %d bytes and expected %d.", bytesRead, chunkLength));
      }
      ResponsePacket response = new ResponsePacket();
      response.prefixCode = AJP13_SEND_BODY_CHUNK_PREFIX;
      response.chunk = chunk;
      return response;
    }

    private static ResponsePacket decodeSendHeaders(DataInputStream dataInputStream)
        throws IOException {
      int httpStatusCode = dataInputStream.readUnsignedShort(); // http_status_code
      String httpStatusMessage = decodeString(dataInputStream); // http_status_msg
      ImmutableMultimap<String, String> responseHeaders =
          decodeResponseHeaders(dataInputStream); // num_headers and response_headers
      ResponsePacket response = new ResponsePacket();
      response.prefixCode = AJP13_SEND_HEADERS_PREFIX;
      response.httpStatusCode = httpStatusCode;
      response.httpStatusMessage = httpStatusMessage;
      response.headers = responseHeaders;
      return response;
    }

    private static ResponsePacket decodeEndResponse(DataInputStream dataInputStream)
        throws IOException {
      boolean reuse = dataInputStream.readByte() == 1; // reuse
      ResponsePacket response = new ResponsePacket();
      response.prefixCode = AJP13_END_RESPONSE_PREFIX;
      response.reuse = reuse;
      return response;
    }

    private static ResponsePacket decodeGetBodyChunk()  {
      ResponsePacket response = new ResponsePacket();
      response.prefixCode = AJP13_GET_BODY_CHUNK_PREFIX;
      return response;
    }
  }
}
