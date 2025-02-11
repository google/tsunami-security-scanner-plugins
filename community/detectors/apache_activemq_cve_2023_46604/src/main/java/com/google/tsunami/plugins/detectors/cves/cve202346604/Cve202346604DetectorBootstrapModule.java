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
package com.google.tsunami.plugins.detectors.cves.cve202346604;

import com.google.inject.Key;
import com.google.inject.Provides;
import com.google.inject.multibindings.OptionalBinder;
import com.google.tsunami.plugin.PluginBootstrapModule;
import com.google.tsunami.plugins.detectors.cves.cve202346604.Annotations.OobSleepDuration;
import javax.net.SocketFactory;

/** An CVE-2023-46604 Guice module that bootstraps the {@link Cve202346604Detector}. */
public final class Cve202346604DetectorBootstrapModule extends PluginBootstrapModule {

  @Override
  protected void configurePlugin() {
    OptionalBinder.newOptionalBinder(
            binder(),
            Key.get(SocketFactory.class, Cve202346604Detector.SocketFactoryInstance.class))
        .setDefault()
        .toInstance(SocketFactory.getDefault());
    registerPlugin(Cve202346604Detector.class);
  }

  @Provides
  @OobSleepDuration
  int provideOobSleepDuration(Cve202346604DetectorConfigs configs) {
    if (configs.oobSleepDuration == 0) {
      return 20;
    }
    return configs.oobSleepDuration;
  }
}
