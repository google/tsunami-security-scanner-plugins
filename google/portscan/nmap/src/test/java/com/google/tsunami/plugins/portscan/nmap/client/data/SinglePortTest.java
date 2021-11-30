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

/** Tests for {@link SinglePort}. */
@RunWith(JUnit4.class)
public class SinglePortTest {

  @Test
  public void getStringRepresentation_withValidValues_returnsCorrectString() {
    SinglePort targetPort =
        SinglePort.create(65535, TransportProtocol.TRANSPORT_PROTOCOL_UNSPECIFIED);

    assertThat(targetPort.getCommandLineRepresentation()).isEqualTo("65535");
  }

  @Test
  public void getStringRepresentation_withProtocol_returnsCorrectString() {
    SinglePort targetPort = SinglePort.create(65535, TransportProtocol.UDP);

    assertThat(targetPort.getCommandLineRepresentation()).isEqualTo("U:65535");
  }

  @Test
  public void create_whenNegativePortValues_throwsException() {
    assertThrows(
        IllegalArgumentException.class,
        () -> SinglePort.create(-1, TransportProtocol.TRANSPORT_PROTOCOL_UNSPECIFIED));
  }

  @Test
  public void create_whenInvalidPortValue_throwsException() {
    assertThrows(
        IllegalArgumentException.class,
        () -> SinglePort.create(99999999, TransportProtocol.TRANSPORT_PROTOCOL_UNSPECIFIED));
  }
}
