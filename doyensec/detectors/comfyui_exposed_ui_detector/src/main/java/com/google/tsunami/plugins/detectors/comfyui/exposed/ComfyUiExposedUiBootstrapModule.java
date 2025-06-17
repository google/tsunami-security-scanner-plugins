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
<<<<<<<< HEAD:doyensec/detectors/comfyui_exposed_ui_detector/src/main/java/com/google/tsunami/plugins/detectors/comfyui/exposed/ComfyUiExposedUiBootstrapModule.java

package com.google.tsunami.plugins.detectors.comfyui.exposed;
========
package com.google.tsunami.plugins.detectors.spring4shell;
>>>>>>>> 5fb4bb5c946155330a4b0971e5d9244b80cfcea2:community/detectors/spring_framework_cve_2022_22965/src/main/java/com/google/tsunami/plugins/detectors/spring4shell/SpringCve202222965DetectorBootstrapModule.java

import static com.google.tsunami.plugins.detectors.spring4shell.Annotations.DelayBetweenRequests;

import com.google.inject.Provides;
import com.google.tsunami.plugin.PluginBootstrapModule;

<<<<<<<< HEAD:doyensec/detectors/comfyui_exposed_ui_detector/src/main/java/com/google/tsunami/plugins/detectors/comfyui/exposed/ComfyUiExposedUiBootstrapModule.java
/** A Guice module that bootstraps the {@link ComfyUiExposedUi}. */
public final class ComfyUiExposedUiBootstrapModule extends PluginBootstrapModule {
========
/** A {@link PluginBootstrapModule} for {@link SpringCve202222965Detector} */
public final class SpringCve202222965DetectorBootstrapModule extends PluginBootstrapModule {
>>>>>>>> 5fb4bb5c946155330a4b0971e5d9244b80cfcea2:community/detectors/spring_framework_cve_2022_22965/src/main/java/com/google/tsunami/plugins/detectors/spring4shell/SpringCve202222965DetectorBootstrapModule.java

  @Override
  protected void configurePlugin() {
    registerPlugin(ComfyUiExposedUi.class);
  }

  @Provides
  @DelayBetweenRequests
  int provideDelayBetweenRequests(SpringCve202222965DetectorConfigs configs) {
    if (configs.delayBetweenRequests == -1) {
      return 3;
    }

    return configs.delayBetweenRequests;
  }
}
