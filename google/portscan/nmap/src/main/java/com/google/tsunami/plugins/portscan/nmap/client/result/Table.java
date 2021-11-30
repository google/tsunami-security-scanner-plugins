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

import static com.google.common.collect.ImmutableList.toImmutableList;

import com.google.auto.value.AutoValue;
import com.google.common.collect.ImmutableList;

/** Table element of nmap XML result. */
@AutoValue
public abstract class Table {
  public abstract String key();

  abstract ImmutableList<Object> valueElements();
  private <T> ImmutableList<T> getElements(Class<T> clazz) {
    return valueElements().stream()
        .filter(clazz::isInstance)
        .map(clazz::cast)
        .collect(toImmutableList());
  }
  public ImmutableList<Table> tables() {
    return getElements(Table.class);
  }
  public ImmutableList<Elem> elems() {
    return getElements(Elem.class);
  }

  public abstract Builder toBuilder();
  public static Builder builder() {
    return new AutoValue_Table.Builder();
  }

  /** Builder for {@link Table}. */
  @AutoValue.Builder
  public abstract static class Builder {
    public abstract Builder setKey(String value);

    abstract ImmutableList.Builder<Object> valueElementsBuilder();
    public Builder addValueElement(Object value) {
      valueElementsBuilder().add(value);
      return this;
    }

    public abstract Table build();
  }
}
