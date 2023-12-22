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
package com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector;

import com.google.tsunami.common.config.annotations.ConfigProperties;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.proto.TargetService;
import java.util.List;

// TODO(b/316472486): Remove ncrack from the config property
@ConfigProperties("plugins.google.detectors.credentials.ncrack")
final class GenericWeakCredentialDetectorConfigs {
  // Path to the ncrack binary.
  String ncrackBinaryPath;

  // Path to the hydra binary
  String hydraBinaryPath;

  /** String value of {@link TargetService} to exclude from scanning. */
  List<String> excludedTargetServices;

  // Whether hydra is enabled
  boolean enableHydra;
}
