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
package com.google.tsunami.plugins.detectors.cves;

import com.google.tsunami.proto.NetworkEndpoint;
import java.io.IOException;
import redis.clients.jedis.JedisPool;

public class JedisPoolFactory {
  JedisPool create(NetworkEndpoint networkEndpoint) throws IOException {
    int port = 6379;
    if (networkEndpoint.hasPort()) {
      port = networkEndpoint.getPort().getPortNumber();
    }
    if (networkEndpoint.hasHostname()) {
      return new JedisPool(networkEndpoint.getHostname().getName(), port);
    } else if (networkEndpoint.hasIpAddress()) {
      return new JedisPool(networkEndpoint.getIpAddress().getAddress(), port);
    } else {
      throw new IOException("Jedis missing target.");
    }
  }
}
