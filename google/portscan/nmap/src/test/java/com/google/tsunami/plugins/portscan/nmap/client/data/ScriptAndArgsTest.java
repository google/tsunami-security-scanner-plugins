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

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.common.collect.ImmutableList;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for {@link ScriptAndArgs}. */
@RunWith(JUnit4.class)
public class ScriptAndArgsTest {

  @Test
  public void create_always_returnsValidObject() {
    ScriptAndArgs scriptAndArgs = ScriptAndArgs.create("test", ImmutableList.of("a", "b"));

    assertThat(scriptAndArgs.scriptName()).isEqualTo("test");
    assertThat(scriptAndArgs.args()).containsExactly("a", "b");
  }

  @Test
  public void create_nullValue_throwsException() {
    assertThrows(
        IllegalArgumentException.class,
        () -> ScriptAndArgs.create(null, ImmutableList.of("a", "b")));
  }
}
