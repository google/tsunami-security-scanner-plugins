/*
 * Copyright 2022 Google LLC
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
package com.google.tsunami.plugins.detectors.rce.cve20199193;

import com.google.inject.Provides;
import com.google.tsunami.plugin.PluginBootstrapModule;

/** A Guice module that bootstraps the {@link Cve20199193Detector}. */
public final class Cve20199193DetectorBootstrapModule extends PluginBootstrapModule {

  @Override
  protected void configurePlugin() {
    registerPlugin(Cve20199193Detector.class);
  }

  @Provides
  ConnectionProviderInterface provideConnectionProvider() {
    return new ConnectionProvider();
  }
}
