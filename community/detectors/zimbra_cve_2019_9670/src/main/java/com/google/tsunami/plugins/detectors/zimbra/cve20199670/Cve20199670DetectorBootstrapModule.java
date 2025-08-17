/*
 * Copyright 2024 Google LLC
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
package com.google.tsunami.plugins.detectors.zimbra.cve20199670;

import com.google.inject.Provides;
import com.google.tsunami.plugin.PluginBootstrapModule;
import com.google.tsunami.plugins.detectors.zimbra.cve20199670.Annotations.OobSleepDuration;

/** A {@link PluginBootstrapModule} for {@link Cve20199670Detector}. */
public final class Cve20199670DetectorBootstrapModule extends PluginBootstrapModule {

  @Override
  protected void configurePlugin() {
    registerPlugin(Cve20199670Detector.class);
  }

  @Provides
  @OobSleepDuration
  int provideOobSleepDuration(Cve20199670DetectorConfigs configs) {
    if (configs.oobSleepDuration == 0) {
      return 10;
    }
    return configs.oobSleepDuration;
  }
}
