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
import static com.google.common.base.Preconditions.checkNotNull;

import com.google.auto.value.AutoValue;
import com.google.common.base.Strings;
import com.google.common.collect.ImmutableList;

/** Nmap script calls and arguments. */
@AutoValue
public abstract class ScriptAndArgs {
  public abstract String scriptName();
  public abstract ImmutableList<String> args();

  public static ScriptAndArgs create(String scriptName, ImmutableList<String> args) {
    checkArgument(!Strings.isNullOrEmpty(scriptName));
    checkNotNull(args);
    return new AutoValue_ScriptAndArgs(scriptName, args);
  }
}
