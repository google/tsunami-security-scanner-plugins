package com.google.tsunami.plugins.detectors.goanywhere;

import com.google.tsunami.plugin.PluginBootstrapModule;

public class Cve20230669DetectorBootstrapModule extends PluginBootstrapModule {

  @Override
  protected void configurePlugin() {
    registerPlugin(Cve20230669VulnDetector.class);
  }
}
