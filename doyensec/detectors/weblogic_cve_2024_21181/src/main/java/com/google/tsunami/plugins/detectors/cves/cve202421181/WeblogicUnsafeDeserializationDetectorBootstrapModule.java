/*
 * Copyright 2025 Google LLC
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

package com.google.tsunami.plugins.detectors.cves.cve202421181;

import static com.google.tsunami.plugins.detectors.cves.cve202421181.Annotations.OobSleepDuration;

import com.google.inject.Provides;
import com.google.inject.multibindings.OptionalBinder;
import com.google.tsunami.plugin.PluginBootstrapModule;
import javax.net.SocketFactory;

/** A Guice module that bootstraps the {@link WeblogicUnsafeDeserializationDetector}. */
public final class WeblogicUnsafeDeserializationDetectorBootstrapModule
    extends PluginBootstrapModule {

  @Override
  protected void configurePlugin() {
    OptionalBinder.newOptionalBinder(binder(), SocketFactory.class)
        .setDefault()
        .toInstance(SocketFactory.getDefault());
    registerPlugin(WeblogicUnsafeDeserializationDetector.class);
  }

  @Provides
  @OobSleepDuration
  int provideOobSleepDuration(WeblogicUnsafeDeserializationDetectorConfigs configs) {
    if (configs.oobSleepDuration == -1) {
      return 5;
    }

    return configs.oobSleepDuration;
  }
}
