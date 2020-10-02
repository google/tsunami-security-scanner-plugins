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

import static com.google.common.base.Preconditions.checkArgument;

import com.google.auto.value.AutoValue;
import com.google.tsunami.proto.TransportProtocol;

/** A range of ports for nmap. */
@AutoValue
public abstract class PortRange implements IPortTarget {
  abstract int startPort();

  abstract int endPort();

  abstract TransportProtocol protocol();

  public static PortRange create(int startPort, int endPort, TransportProtocol protocol) {
    // Ports in the range of 0-65535. The following checks verifies that 0 <= start < end <= 65535
    checkArgument(startPort < endPort, "Expected %s < %s", startPort, endPort);
    checkArgument(0 <= startPort, "Expected 0 <= %s", startPort);
    checkArgument(endPort <= MAX_PORT_NUMBER, "Expected %s <= %s", endPort, MAX_PORT_NUMBER);
    return new AutoValue_PortRange(startPort, endPort, protocol);
  }

  @Override
  public String getCommandLineRepresentation() {
    return String.format(
        "%s%d-%d", IPortTarget.protocolCliString(protocol()), startPort(), endPort());
  }

  @Override
  public boolean isProtocolSpecified() {
    return protocol() != TransportProtocol.TRANSPORT_PROTOCOL_UNSPECIFIED;
  }
}
