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
package com.google.tsunami.plugins.portscan.nmap.client.data;

import com.google.tsunami.proto.TransportProtocol;

/**
 * A target port for the nmap client.
 *
 * <p>Ports are passed to nmap command line and must have a valid string representation supported by
 * nmap.
 */
public interface IPortTarget {

  public static String protocolCliString(TransportProtocol protocol) {
    switch (protocol) {
      case TCP:
        return "T:";
      case UDP:
        return "U:";
      case SCTP:
        return "S:";
      default:
        return "";
    }
  }

  int MAX_PORT_NUMBER = 65535;

  boolean isProtocolSpecified();

  String getCommandLineRepresentation();
}
