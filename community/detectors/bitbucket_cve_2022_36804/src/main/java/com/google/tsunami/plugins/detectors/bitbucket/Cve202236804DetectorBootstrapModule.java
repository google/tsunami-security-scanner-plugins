package com.google.tsunami.plugins.detectors.bitbucket;

import com.google.tsunami.plugin.PluginBootstrapModule;

public class Cve202236804DetectorBootstrapModule extends PluginBootstrapModule {

  @Override
  protected void configurePlugin() {
    registerPlugin(Cve202236804VulnDetector.class);
  }
}
