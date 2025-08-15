package com.google.tsunami.plugins.detectors.templateddetector;

import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.templatedplugin.proto.PluginAction;

/** ActionRunner is an interface that defines how an action is run. */
public interface ActionRunner {
  // Run the action and return true if it succeeded.
  public boolean run(NetworkService service, PluginAction action, Environment environment);
}
