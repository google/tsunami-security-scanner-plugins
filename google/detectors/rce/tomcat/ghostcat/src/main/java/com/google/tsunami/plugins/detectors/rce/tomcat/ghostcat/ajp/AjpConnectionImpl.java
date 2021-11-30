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

import static com.google.common.base.Preconditions.checkNotNull;

import com.google.inject.assistedinject.Assisted;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import javax.inject.Inject;

/**
 * Specific implementation of the Ghostcat exploit. Tries to execute a crafted AjpForwardRequest
 * against an exposed AJP connector.
 */
public final class AjpConnectionImpl implements AjpConnection {
  private final Socket socket;
  private final String ip;
  private final int port;

  @Inject
  AjpConnectionImpl(Socket socket, @Assisted String ip, @Assisted int port) {
    this.socket = checkNotNull(socket);
    this.ip = checkNotNull(ip);
    this.port = port;
  }

  @Override
  public AjpResponse performGhostcat(String reqUri, String path) throws IOException {
    socket.connect(new InetSocketAddress(ip, port));
    try (OutputStream outputStream = socket.getOutputStream();
        InputStream inputStream = socket.getInputStream()) {
      outputStream.write(GhostcatAjpForwardRequest.craft(ip, port, reqUri, path));
      outputStream.flush();
      return AjpResponse.read(inputStream);
    }
  }
}
