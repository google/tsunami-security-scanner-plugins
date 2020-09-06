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
package com.google.tsunami.plugins.portscan.nmap.option.validator;

import static org.junit.Assert.assertThrows;

import com.beust.jcommander.ParameterException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for {@link PortRangeValidator}. */
@RunWith(JUnit4.class)
public class PortRangeValidatorTest {
  @Test
  public void validate_withValidPortRange_doesNotThrow() {
    try {
      new PortRangeValidator().validate("port-ranges-target", "80,8080,15000-16000");
    } catch (ParameterException e) {
      throw new AssertionError("Unexpected ParameterException: " + e);
    }
  }

  @Test
  public void validate_invalidInterval_throwsParameterException() {
    assertThrows(
        ParameterException.class,
        () -> new PortRangeValidator().validate("port-ranges-target", "15000-16000-17000"));
    assertThrows(
        ParameterException.class,
        () -> new PortRangeValidator().validate("port-ranges-target", "16000-15000"));
  }

  @Test
  public void validate_invalidIntegers_throwsParameterException() {
    assertThrows(
        ParameterException.class,
        () -> new PortRangeValidator().validate("port-ranges-target", "A-B"));
  }

  @Test
  public void validate_invalidPorts_throwsParameterException() {
    assertThrows(
        ParameterException.class,
        () -> new PortRangeValidator().validate("port-ranges-target", "65536"));
  }
}
