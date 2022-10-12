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
package com.google.tsunami.plugins.detectors.directorytraversal.genericpathtraversaldetector;

import com.google.common.collect.ImmutableSet;
import com.google.inject.Provides;
import com.google.tsunami.plugin.PluginBootstrapModule;

/** A Guice module that bootstraps the {@link GenericPathTraversalDetector}. */
public final class GenericPathTraversalDetectorBootstrapModule extends PluginBootstrapModule {

  @Override
  protected void configurePlugin() {
    // registerPlugin method is required in order for the Tsunami scanner to identify the plugin.
    registerPlugin(GenericPathTraversalDetector.class);
  }

  @Provides
  GenericPathTraversalDetectorConfig provideGenericPathTraversalDetectorConfig() {
    return GenericPathTraversalDetectorConfig.create(
        ImmutableSet.of(new GetParameterInjection(), new PathParameterInjection()),
        /* maxCrawledUrlsToFuzz= */ 50,
        /* maxExploitsToTest= */ 4);
  }
}
