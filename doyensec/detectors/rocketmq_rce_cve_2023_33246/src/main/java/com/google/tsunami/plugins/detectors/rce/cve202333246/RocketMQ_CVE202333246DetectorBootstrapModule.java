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
package com.google.tsunami.plugins.detectors.rce.cve202333246;

import com.google.inject.Provides;
import com.google.tsunami.plugin.PluginBootstrapModule;

/** A module for bootstrapping the {@link RocketMQ_CVE202333246Detector}. */
public final class RocketMQ_CVE202333246DetectorBootstrapModule extends PluginBootstrapModule {

  @Override
  protected void configurePlugin() {
    registerPlugin(RocketMQ_CVE202333246Detector.class);
  }

  @Provides
  @Annotations.OobSleepDuration
  int provideOobSleepDuration(RocketMQ_CVE202333246DetectorConfig configs) {
    if (configs.oobSleepDuration == 0) {
      return 10;
    }
    return configs.oobSleepDuration;
  }
}
