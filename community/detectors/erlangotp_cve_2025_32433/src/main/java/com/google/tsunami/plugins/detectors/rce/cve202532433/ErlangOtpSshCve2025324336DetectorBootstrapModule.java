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
package com.google.tsunami.plugins.detectors.rce.cve202532433;

import com.google.inject.Provides;
import com.google.tsunami.plugin.PluginBootstrapModule;
import com.google.tsunami.plugins.detectors.rce.cve202532433.Annotations.OobSleepDuration;
import com.google.tsunami.plugins.detectors.rce.cve202532433.Annotations.SocketFactoryInstance;
import javax.net.SocketFactory;

/** A module for bootstrapping the {@link ErlangOtpSshCve2025324336Detector}. */
public final class ErlangOtpSshCve2025324336DetectorBootstrapModule extends PluginBootstrapModule {

  @Override
  protected void configurePlugin() {
    registerPlugin(ErlangOtpSshCve2025324336Detector.class);
  }

  @Provides
  @OobSleepDuration
  int provideOobSleepDuration(ErlangOtpSshCve2025324336DetectorConfig configs) {
    if (configs.oobSleepDuration == 0) {
      return 2;
    }
    return configs.oobSleepDuration;
  }

  @Provides
  @SocketFactoryInstance
  SocketFactory provideSocketFactoryInstance() {
    return SocketFactory.getDefault();
  }
}
