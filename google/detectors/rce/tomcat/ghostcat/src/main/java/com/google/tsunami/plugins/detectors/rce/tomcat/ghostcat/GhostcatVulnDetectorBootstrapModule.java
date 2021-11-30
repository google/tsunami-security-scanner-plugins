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
package com.google.tsunami.plugins.detectors.rce.tomcat.ghostcat;

import com.google.inject.assistedinject.FactoryModuleBuilder;
import com.google.tsunami.plugin.PluginBootstrapModule;
import com.google.tsunami.plugins.detectors.rce.tomcat.ghostcat.ajp.AjpConnection;
import com.google.tsunami.plugins.detectors.rce.tomcat.ghostcat.ajp.AjpConnectionImpl;

/** A {@link PluginBootstrapModule} for {@link GhostcatVulnDetector}. */
public final class GhostcatVulnDetectorBootstrapModule extends PluginBootstrapModule {

  private final boolean forTesting;

  public GhostcatVulnDetectorBootstrapModule() {
    this(false);
  }

  public GhostcatVulnDetectorBootstrapModule(boolean forTesting) {
    this.forTesting = forTesting;
  }

  @Override
  protected void configurePlugin() {
    registerPlugin(GhostcatVulnDetector.class);

    if (!forTesting) {
      install(
          new FactoryModuleBuilder()
              .implement(AjpConnection.class, AjpConnectionImpl.class)
              .build(AjpConnection.Factory.class));
    }
  }
}
