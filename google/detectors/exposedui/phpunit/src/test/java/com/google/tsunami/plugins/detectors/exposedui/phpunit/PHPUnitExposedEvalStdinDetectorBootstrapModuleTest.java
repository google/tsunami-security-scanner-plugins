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

import static com.google.common.truth.Truth.assertThat;
import static java.nio.file.StandardCopyOption.REPLACE_EXISTING;

import com.google.inject.AbstractModule;
import com.google.inject.Guice;
import com.google.tsunami.plugins.detectors.exposedui.phpunit.PHPUnitExposedEvalStdinDetectorBootstrapModule.Mode;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import javax.inject.Inject;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link PHPUnitExposedEvalStdinDetectorBootstrapModule}. */
@RunWith(JUnit4.class)
public class PHPUnitExposedEvalStdinDetectorBootstrapModuleTest {
  @Rule public final TemporaryFolder tempFolder = new TemporaryFolder();

  private static final String TEST_SCRIPT_PATH =
      "com/google/tsunami/plugins/detectors/exposedui/phpunit/testdata/test_phpunit_path_list.txt";

  private PHPUnitExposedEvalStdinDetectorConfigs configs;

  @Inject private PHPUnitExposedEvalStdinDetectorBootstrapModule module;

  @Before
  public void setUp() {
    configs = new PHPUnitExposedEvalStdinDetectorConfigs();
    Guice.createInjector(
            new AbstractModule() {
              @Override
              protected void configure() {
                bind(PHPUnitExposedEvalStdinDetectorConfigs.class).toInstance(configs);
              }
            })
        .injectMembers(this);
  }

  @Test
  public void provideMode_withNoConfig_returnDefault() {
    assertThat(module.provideMode(configs)).isEqualTo(Mode.DEFAULT);
  }

  @Test
  public void provideMode_withConfig_returnConfiguredMode() {
    configs.mode = "CUSTOM";
    assertThat(module.provideMode(configs)).isEqualTo(Mode.CUSTOM);
  }

  @Test
  public void provideScriptPaths_withNoConfig_returnEmpty() throws IOException {
    assertThat(module.provideDefaultScriptPaths(configs)).isEmpty();
  }

  @Test
  public void provideScriptPaths_inCustomRunMode_returnPathsFromFile() throws IOException {
    configs.mode = "CUSTOM";
    Path configPath = copyPathListFileToTestDir();
    configs.scriptPathsFile = configPath.toString();
    assertThat(module.provideDefaultScriptPaths(configs))
        .containsExactly("foo/eval-stdin.php", "bar/eval-stdin.php", "foo/bar/eval-stdin.php");
  }

  @Test
  public void provideScriptPaths_inFullRunMode_returnBuiltInPaths() throws IOException {
    configs.mode = "FULL";
    assertThat(module.provideDefaultScriptPaths(configs)).hasSize(519);
  }

  private Path copyPathListFileToTestDir() throws IOException {
    File destinationFile = tempFolder.newFile("path_list.txt");
    Path destinationFilePath = destinationFile.toPath();
    InputStream stream = getClass().getClassLoader().getResourceAsStream(TEST_SCRIPT_PATH);
    Files.copy(stream, destinationFilePath, REPLACE_EXISTING);
    return destinationFilePath;
  }
}
