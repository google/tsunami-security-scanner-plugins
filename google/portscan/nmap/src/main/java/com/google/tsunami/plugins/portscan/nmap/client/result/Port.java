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
import org.checkerframework.checker.nullness.qual.Nullable;

/** Port element of nmap XML result. */
@AutoValue
public abstract class Port {
  public abstract String protocol();
  public abstract String portId();
  public abstract State state();
  @Nullable public abstract Owner owner();
  @Nullable public abstract Service service();
  public abstract ImmutableList<Script> scripts();

  public abstract Builder toBuilder();
  public static Builder builder() {
    return new AutoValue_Port.Builder();
  }

  /** Builder for {@link Port}. */
  @AutoValue.Builder
  public abstract static class Builder {
    public abstract Builder setProtocol(String value);
    public abstract Builder setPortId(String value);
    public abstract Builder setState(State value);
    public abstract Builder setOwner(Owner value);
    public abstract Builder setService(Service value);

    public abstract Builder setScripts(Iterable<Script> value);
    abstract ImmutableList.Builder<Script> scriptsBuilder();
    public Builder addScript(Script value) {
      scriptsBuilder().add(value);
      return this;
    }

    public abstract Port build();
  }
}
