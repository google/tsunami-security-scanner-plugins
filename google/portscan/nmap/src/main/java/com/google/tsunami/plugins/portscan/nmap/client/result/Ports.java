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
package com.google.tsunami.plugins.portscan.nmap.client.result;

import com.google.auto.value.AutoValue;
import com.google.common.collect.ImmutableList;

/** Ports element of nmap XML result. */
@AutoValue
public abstract class Ports {
  public abstract ImmutableList<ExtraPorts> extraPorts();
  public abstract ImmutableList<Port> ports();

  public abstract Builder toBuilder();
  public static Builder builder() {
    return new AutoValue_Ports.Builder();
  }

  /** Builder for {@link Ports}. */
  @AutoValue.Builder
  public abstract static class Builder {
    public abstract Builder setExtraPorts(Iterable<ExtraPorts> value);
    abstract ImmutableList.Builder<ExtraPorts> extraPortsBuilder();
    public Builder addExtraPorts(ExtraPorts value) {
      extraPortsBuilder().add(value);
      return this;
    }

    public abstract Builder setPorts(Iterable<Port> value);
    abstract ImmutableList.Builder<Port> portsBuilder();
    public Builder addPort(Port value) {
      portsBuilder().add(value);
      return this;
    }

    public abstract Ports build();
  }
}
