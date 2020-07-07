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

/** TaskBegin element of nmap XML result. */
@AutoValue
public abstract class TaskBegin {
  public abstract String task();
  public abstract String time();
  public abstract String extraInfo();

  public abstract Builder toBuilder();
  public static Builder builder() {
    return new AutoValue_TaskBegin.Builder();
  }

  /** Builder for {@link TaskBegin}. */
  @AutoValue.Builder
  public abstract static class Builder {
    public abstract Builder setTask(String value);
    public abstract Builder setTime(String value);
    public abstract Builder setExtraInfo(String value);

    public abstract TaskBegin build();
  }
}
