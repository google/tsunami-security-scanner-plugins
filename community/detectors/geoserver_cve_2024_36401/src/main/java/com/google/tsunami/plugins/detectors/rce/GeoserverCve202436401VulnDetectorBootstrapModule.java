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
package com.google.tsunami.plugins.detectors.rce;

import com.google.inject.Provides;
import com.google.tsunami.plugin.PluginBootstrapModule;
import com.google.tsunami.plugins.detectors.rce.Annotations.OobSleepDuration;

/**
 * A Geoserver Cve-2024-36401 Rce Detector Guice module that bootstraps the {@link
 * GeoserverCve202436401VulnDetector}.
 */
public final class GeoserverCve202436401VulnDetectorBootstrapModule extends PluginBootstrapModule {

  @Override
  protected void configurePlugin() {
    registerPlugin(GeoserverCve202436401VulnDetector.class);
  }

  @Provides
  @OobSleepDuration
  int provideOobSleepDuration(GeoserverRceDetectorConfigs configs) {
    if (configs.oobSleepDuration == 0) {
      return 10;
    }
    return configs.oobSleepDuration;
  }
}
