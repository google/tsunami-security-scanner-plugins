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

/** TcpTsSequence element of nmap XML result. */
@AutoValue
public abstract class TcpTsSequence {
  public abstract String clazz();
  public abstract String values();

  public abstract Builder toBuilder();
  public static Builder builder() {
    return new AutoValue_TcpTsSequence.Builder();
  }

  /** Builder for {@link TcpTsSequence}. */
  @AutoValue.Builder
  public abstract static class Builder {
    public abstract Builder setClazz(String value);
    public abstract Builder setValues(String value);

    public abstract TcpTsSequence build();
  }
}
