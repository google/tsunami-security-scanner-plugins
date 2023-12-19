package com.google.tsunami.plugins.detectors.rce.torchserve;

import com.google.tsunami.plugin.PluginBootstrapModule;

/** A {@link PluginBootstrapModule} for {@link TorchServeManagementApiDetector}. */
public final class TorchServeManagementApiDetectorBootstrapModule extends PluginBootstrapModule {

  @Override
  protected void configurePlugin() {
    registerPlugin(TorchServeManagementApiDetector.class);
  }
}
