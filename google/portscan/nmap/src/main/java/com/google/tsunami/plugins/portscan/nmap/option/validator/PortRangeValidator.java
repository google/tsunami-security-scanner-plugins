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

import com.beust.jcommander.IParameterValidator;
import com.beust.jcommander.ParameterException;
import com.google.common.base.Splitter;
import com.google.common.base.Strings;

/** Base command line flag validator for a range of ports. */
public final class PortRangeValidator implements IParameterValidator {
  public boolean isValidPort(int port) {
    return port >= 0 && port <= 0xFFFF;
  }

  public boolean isValidPortRange(String value) {
    int first;
    int second;
    String[] range = value.split("-", -1);
    try {
      if (range.length != 0
          && (range[0].startsWith("T:")
              || range[0].startsWith("U:")
              || range[0].startsWith("S:"))) {
        range[0] = range[0].substring(2);
      }
      if (range.length == 1) {
        first = Integer.parseInt(range[0]);
        second = first;
      } else if (range.length == 2) {
        first = Integer.parseInt(range[0]);
        second = Integer.parseInt(range[1]);
      } else {
        return false;
      }
    } catch (NumberFormatException e) {
      return false;
    }
    return isValidPort(first) && isValidPort(second) && first <= second;
  }

  @Override
  public void validate(String name, String value) {
    if (Strings.isNullOrEmpty(value)) {
      return;
    }
    for (String range : Splitter.on(',').split(value)) {
      if (!isValidPortRange(range)) {
        throw new ParameterException(
            String.format(
                "Parameter %s should point to valid port ranges, got invalid range '%s'",
                name, range));
      }
    }
  }
}
