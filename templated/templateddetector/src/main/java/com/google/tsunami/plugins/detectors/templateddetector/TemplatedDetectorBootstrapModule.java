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
package com.google.tsunami.plugins.detectors.templateddetector;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.flogger.GoogleLogger;
import com.google.common.io.Resources;
import com.google.common.reflect.ClassPath;
import com.google.tsunami.plugin.PluginBootstrapModule;
import com.google.tsunami.plugin.PluginType;
import com.google.tsunami.templatedplugin.proto.TemplatedPlugin;
import java.io.IOException;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import org.jspecify.annotations.Nullable;

/** Bootstrap module to dynamically load templated plugins. */
public final class TemplatedDetectorBootstrapModule extends PluginBootstrapModule {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  @SuppressWarnings("MutableGuiceModule")
  private final Map<String, TemplatedDetector> detectors = new HashMap<>();

  @SuppressWarnings("MutableGuiceModule")
  private boolean forceLoadDetectors = false;

  ImmutableMap<String, TemplatedDetector> getDetectors() {
    return ImmutableMap.copyOf(this.detectors);
  }

  // setForceLoadDetectors is used by unit tests to force loading disabled plugins and ensure
  // they are tested as well.
  void setForceLoadDetectors(boolean forceLoadDetectors) {
    this.forceLoadDetectors = forceLoadDetectors;
  }

  @Override
  protected void configurePlugin() {
    for (String resourceName : getResourceNames()) {
      loadPlugin(resourceName);
    }
  }

  @SuppressWarnings("ProtoParseWithRegistry")
  private @Nullable TemplatedPlugin readPlugin(String resourceName) {
    try {
      URL url = Resources.getResource(resourceName);
      var byteStream = Resources.toByteArray(url);
      return TemplatedPlugin.parseFrom(byteStream);
    } catch (IOException e) {
      logger.atSevere().withCause(e).log("Failed to read plugin: %s", resourceName);
      return null;
    }
  }

  private void loadPlugin(String resourceName) {
    var pluginProto = readPlugin(resourceName);
    if (pluginProto == null) {
      return;
    }

    if (!this.forceLoadDetectors && pluginProto.getConfig().getDisabled()) {
      logger.atInfo().log("Skipping disabled plugin: %s", pluginProto.getInfo().getName());
      return;
    }

    var info = pluginProto.getInfo();
    if (this.detectors.containsKey(info.getName())) {
      throw new IllegalStateException(
          String.format("Plugin '%s' already registered. Are there two plugins with the same name?", info.getName()));
    }

    var detector = new TemplatedDetector(pluginProto);
    detectors.put(info.getName(), detector);
    registerDynamicPlugin(
        PluginType.VULN_DETECTION, info.getName(), info.getAuthor(), false, false, detector);
  }

  private ImmutableList<String> getResourceNames() {
    ImmutableList.Builder<String> resourceNames = ImmutableList.builder();
    ClassPath classPath = null;

    try {
      classPath = ClassPath.from(ClassLoader.getSystemClassLoader());
    } catch (IOException e) {
      logger.atSevere().withCause(e).log("Failed to dynamically load the list of plugins.");
      return ImmutableList.of();
    }

    for (var resource : classPath.getResources()) {
      var resourceName = resource.getResourceName();
      if (!resourceName.contains("templateddetector/plugins/")) {
        continue;
      }

      if (!resourceName.endsWith(".binarypb") || resourceName.endsWith("_test.binarypb")) {
        continue;
      }

      resourceNames.add(resourceName);
    }

    return resourceNames.build();
  }
}
