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
package com.google.tsunami.plugins.fingerprinters.web;

import com.google.common.collect.ImmutableMap;
import com.google.inject.Provides;
import com.google.inject.assistedinject.FactoryModuleBuilder;
import com.google.tsunami.plugin.PluginBootstrapModule;
import com.google.tsunami.plugins.fingerprinters.web.crawl.SimpleCrawlerModule;
import com.google.tsunami.plugins.fingerprinters.web.data.FingerprintData;
import com.google.tsunami.plugins.fingerprinters.web.data.FingerprintLoader;
import com.google.tsunami.plugins.fingerprinters.web.data.ResourceFingerprintLoaderModule;
import com.google.tsunami.plugins.fingerprinters.web.detection.VersionDetector;
import com.google.tsunami.plugins.fingerprinters.web.proto.SoftwareIdentity;
import java.io.IOException;
import javax.inject.Singleton;

/** A {@link PluginBootstrapModule} for {@link WebServiceFingerprinter}. */
public final class WebServiceFingerprinterBootstrapModule extends PluginBootstrapModule {

  @Override
  protected void configurePlugin() {
    install(new SimpleCrawlerModule(/*maxActiveThreads=*/ 8));
    install(new ResourceFingerprintLoaderModule());
    install(new FactoryModuleBuilder().build(VersionDetector.Factory.class));

    registerPlugin(WebServiceFingerprinter.class);
  }

  @Singleton
  @Provides
  ImmutableMap<SoftwareIdentity, FingerprintData> provideFingerprintData(
      FingerprintLoader fingerprintLoader) throws IOException {
    return fingerprintLoader.loadFingerprints();
  }
}
