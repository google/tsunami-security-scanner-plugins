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

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.tsunami.proto.TransportProtocol;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for {@link PortRange}. */
@RunWith(JUnit4.class)
public class PortRangeTest {

  @Test
  public void getStringRepresentation_withValidValues_returnsCorrectString() {
    PortRange targetPort =
        PortRange.create(0, 65535, TransportProtocol.TRANSPORT_PROTOCOL_UNSPECIFIED);

    assertThat(targetPort.getCommandLineRepresentation()).isEqualTo("0-65535");
  }

  @Test
  public void getStringRepresentation_withProtocol_returnsCorrectString() {
    PortRange targetPort = PortRange.create(0, 65535, TransportProtocol.TCP);

    assertThat(targetPort.getCommandLineRepresentation()).isEqualTo("T:0-65535");
  }

  @Test
  public void create_whenNegativePortValues_throwsException() {
    assertThrows(
        IllegalArgumentException.class,
        () -> PortRange.create(-1, 65535, TransportProtocol.TRANSPORT_PROTOCOL_UNSPECIFIED));
  }

  @Test
  public void create_whenOutOfOrderPortValues_throwsException() {
    assertThrows(
        IllegalArgumentException.class,
        () -> PortRange.create(65535, 0, TransportProtocol.TRANSPORT_PROTOCOL_UNSPECIFIED));
  }

  @Test
  public void create_whenInvalidPortValue_throwsException() {
    assertThrows(
        IllegalArgumentException.class,
        () -> PortRange.create(0, 99999999, TransportProtocol.TRANSPORT_PROTOCOL_UNSPECIFIED));
  }
}
