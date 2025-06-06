package com.google.tsunami.plugins.detectors.mlflow;

import com.google.tsunami.plugin.PluginBootstrapModule;

public final class MlflowWeakCredentialDetectorBootstrapModule extends PluginBootstrapModule {

  @Override
  protected void configurePlugin() {
    // Register the MlflowWeakCredentialDetector.
    // Tsunami's plugin infrastructure will use this to instantiate and execute the detector.
    registerPlugin(MlflowWeakCredentialDetector.class);
  }
}
