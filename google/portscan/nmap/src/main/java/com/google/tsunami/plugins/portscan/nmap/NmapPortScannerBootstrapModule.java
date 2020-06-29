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
package com.google.tsunami.plugins.portscan.nmap;

import com.google.common.base.Strings;
import com.google.common.collect.ImmutableList;
import com.google.inject.Provides;
import com.google.tsunami.plugin.PluginBootstrapModule;
import com.google.tsunami.plugins.portscan.nmap.client.NmapBinaryPath;
import java.io.FileNotFoundException;
import java.nio.file.Files;
import java.nio.file.Paths;

/** A {@link PluginBootstrapModule} for {@link NmapPortScanner}. */
public class NmapPortScannerBootstrapModule extends PluginBootstrapModule {
  private static final ImmutableList<String> DEFAULT_NMAP_BINARY_PATHS =
      ImmutableList.of("/usr/bin/nmap", "/usr/local/bin/nmap");

  @Override
  protected void configurePlugin() {
    registerPlugin(NmapPortScanner.class);
  }

  @Provides
  @NmapBinaryPath
  public String provideNmapBinaryPath(NmapPortScannerConfigs configs) throws FileNotFoundException {
    if (!Strings.isNullOrEmpty(configs.nmapBinaryPath)) {
      if (Files.exists(Paths.get(configs.nmapBinaryPath))) {
        return configs.nmapBinaryPath;
      }

      throw new FileNotFoundException(
          String.format(
              "Nmap binary '%s' from config file was not found.", configs.nmapBinaryPath));
    }

    for (String nmapBinaryPath : DEFAULT_NMAP_BINARY_PATHS) {
      if (Files.exists(Paths.get(nmapBinaryPath))) {
        return nmapBinaryPath;
      }
    }

    throw new FileNotFoundException(
        "Unable to find a valid nmap binary. Make sure Tsunami config contains a valid nmap binary"
            + " path.");
  }
}
