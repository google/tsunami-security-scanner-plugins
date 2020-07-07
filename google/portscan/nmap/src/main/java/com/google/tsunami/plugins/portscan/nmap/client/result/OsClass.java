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

/** OsClass element of nmap XML result. */
@AutoValue
public abstract class OsClass {
  public abstract String vendor();
  public abstract String osGen();
  public abstract String type();
  public abstract String accuracy();
  public abstract String osFamily();
  public abstract ImmutableList<Cpe> cpes();

  public abstract Builder toBuilder();
  public static Builder builder() {
    return new AutoValue_OsClass.Builder();
  }

  /** Builder for {@link OsClass}. */
  @AutoValue.Builder
  public abstract static class Builder {
    public abstract Builder setVendor(String value);
    public abstract Builder setOsGen(String value);
    public abstract Builder setType(String value);
    public abstract Builder setAccuracy(String value);
    public abstract Builder setOsFamily(String value);
    public abstract Builder setCpes(Iterable<Cpe> value);
    abstract ImmutableList.Builder<Cpe> cpesBuilder();
    public Builder addCpe(Cpe value) {
      cpesBuilder().add(value);
      return this;
    }

    public abstract OsClass build();
  }
}
