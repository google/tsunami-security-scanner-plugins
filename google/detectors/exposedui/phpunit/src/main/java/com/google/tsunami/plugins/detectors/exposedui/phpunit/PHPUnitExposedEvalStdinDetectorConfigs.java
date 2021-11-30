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

import com.google.tsunami.common.config.annotations.ConfigProperties;

@ConfigProperties("plugins.google.detector.exposed_ui.phpunit")
final class PHPUnitExposedEvalStdinDetectorConfigs {
  // Scanning Mode, can be DEFAULT, CUSTOM or FULL.
  // DEFAULT: Scans for the exact path reported in cve-2017-9841.
  // CUSTOM: Reads in newline separated paths and scans those paths instead for eval-stdin.php.
  // FULL: Scans for all the paths defined in data/phpunit_path_list.txt
  String mode;

  // The custom paths to eval-stdin.php script
  String scriptPathsFile;
}
