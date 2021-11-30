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
package com.google.tsunami.plugins.detectors.exposedui.phpunit;

import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.common.base.Strings;
import com.google.common.collect.ImmutableList;
import com.google.common.io.Resources;
import com.google.inject.Provides;
import com.google.tsunami.plugin.PluginBootstrapModule;
import com.google.tsunami.plugins.detectors.exposedui.phpunit.Annotations.RunMode;
import com.google.tsunami.plugins.detectors.exposedui.phpunit.Annotations.ScriptPaths;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/** A Guice module that bootstraps the {@link PHPUnitExposedEvalStdinDetector}. */
public final class PHPUnitExposedEvalStdinDetectorBootstrapModule extends PluginBootstrapModule {
  private static final String DEFAULT_SCRIPT_PATH =
      "com/google/tsunami/plugins/detectors/exposedui/phpunit/data/phpunit_path_list.txt";

  @Override
  protected void configurePlugin() {
    registerPlugin(PHPUnitExposedEvalStdinDetector.class);
  }

  @Provides
  @RunMode
  Mode provideMode(PHPUnitExposedEvalStdinDetectorConfigs configs) {
    if ("CUSTOM".equals(configs.mode)) {
      return Mode.CUSTOM;
    } else if ("FULL".equals(configs.mode)) {
      return Mode.FULL;
    }
    return Mode.DEFAULT;
  }

  @Provides
  @ScriptPaths
  ImmutableList<String> provideDefaultScriptPaths(PHPUnitExposedEvalStdinDetectorConfigs configs)
      throws IOException {
    Mode runMode = provideMode(configs);
    if (runMode == Mode.CUSTOM) {
      if (!Strings.isNullOrEmpty(configs.scriptPathsFile)) {
        return ImmutableList.copyOf(readScriptPathsFromFile(configs.scriptPathsFile));
      } else {
        throw new IllegalArgumentException(
            "script_path_file field has to be non-empty when running in CUSTOM mode");
      }
    } else if (runMode == Mode.FULL) {
      return ImmutableList.copyOf(
          Resources.readLines(Resources.getResource(DEFAULT_SCRIPT_PATH), UTF_8));
    }
    return ImmutableList.of();
  }

  private static List<String> readScriptPathsFromFile(String filename) throws IOException {
    try (Stream<String> lines = Files.lines(Paths.get(filename))) {
      return lines.collect(Collectors.toList());
    }
  }

  /** The run mode for {@link PHPUnitExposedEvalStdinDetector}. */
  public enum Mode {
    DEFAULT,
    CUSTOM,
    FULL
  }
}
