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
package com.google.tsunami.plugins.detectors.cves.cve202144228;

import com.google.tsunami.plugin.PluginBootstrapModule;
import com.google.tsunami.plugins.detectors.cves.cve202144228.crawl.SimpleCrawlerModule;

/**
 * An CVE-2021-44228 Guice module that bootstraps the {@link Cve202144228VulnDetector}.
 */
public final class Cve202144228DetectorBootstrapModule extends PluginBootstrapModule {

  @Override
  protected void configurePlugin() {
    install(new SimpleCrawlerModule(/*maxActiveThreads=*/ 8));
    registerPlugin(Cve202144228VulnDetector.class);
  }
}
