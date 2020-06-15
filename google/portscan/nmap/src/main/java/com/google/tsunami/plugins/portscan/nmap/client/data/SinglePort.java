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

/** A single port. */
@AutoValue
public abstract class SinglePort implements IPortTarget {
  abstract int port();

  public static SinglePort create(int port) {
    checkArgument(0 <= port, "Expected 0 <= %s", port);
    checkArgument(port <= MAX_PORT_NUMBER, "Expected %s <= %s", port, MAX_PORT_NUMBER);
    return new AutoValue_SinglePort(port);
  }

  @Override
  public String getCommandLineRepresentation() {
    return Integer.toString(port());
  }
}
