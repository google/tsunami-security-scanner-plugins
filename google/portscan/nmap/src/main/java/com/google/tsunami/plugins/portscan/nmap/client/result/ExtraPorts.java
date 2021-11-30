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

/** ExtraPorts element of nmap XML result. */
@AutoValue
public abstract class ExtraPorts {
  public abstract String state();
  public abstract String count();
  public abstract ImmutableList<ExtraReasons> extraReasons();

  public abstract Builder toBuilder();
  public static Builder builder() {
    return new AutoValue_ExtraPorts.Builder();
  }

  /** Builder for {@link ExtraPorts}. */
  @AutoValue.Builder
  public abstract static class Builder {
    public abstract Builder setState(String value);
    public abstract Builder setCount(String value);
    public abstract Builder setExtraReasons(Iterable<ExtraReasons> value);
    abstract ImmutableList.Builder<ExtraReasons> extraReasonsBuilder();
    public Builder addExtraReasons(ExtraReasons value) {
      extraReasonsBuilder().add(value);
      return this;
    }

    public abstract ExtraPorts build();
  }
}
