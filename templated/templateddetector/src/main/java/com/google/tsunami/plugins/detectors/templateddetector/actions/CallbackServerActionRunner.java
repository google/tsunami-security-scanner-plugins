package com.google.tsunami.plugins.detectors.templateddetector.actions;

import static com.google.common.base.Preconditions.checkNotNull;

import com.google.common.flogger.GoogleLogger;
import com.google.tsunami.plugin.TcsClient;
import com.google.tsunami.plugins.detectors.templateddetector.ActionRunner;
import com.google.tsunami.plugins.detectors.templateddetector.Environment;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.templatedplugin.proto.PluginAction;

/** CallbackServerActionRunner is an ActionRunner that runs callback server related actions. */
public final class CallbackServerActionRunner implements ActionRunner {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private TcsClient tcsClient = null;
  private final boolean debug;

  public CallbackServerActionRunner(TcsClient tcsClient, boolean debug) {
    this.tcsClient = checkNotNull(tcsClient);
    this.debug = debug;
  }

  @Override
  public boolean run(NetworkService service, PluginAction action, Environment environment) {
    var actionType = action.getCallbackServer().getActionType();

    switch (actionType) {
      case CHECK:
        return performActionCheck(environment);
      default:
        logger.atSevere().log("Unknown callback server action type: %s", actionType);
        return false;
    }
  }

  private boolean performActionCheck(Environment environment) {
     if (!this.tcsClient.isCallbackServerEnabled()) {
      logger.atInfo().log("Callback server is not enabled but workflow defined callback server action. Is the plugin misconfigured?");
      return false;
    }

    var secret = environment.get("T_CBS_SECRET");
    if (secret == null) {
      logger.atInfo().log("Callback server action defined, but the secret was not found. Please report this to the tsunami developers.");
      return false;
    }

    if (this.debug) {
      logger.atInfo().log("Checking if callback server has logs for secret '%s'", secret);
    }

    return this.tcsClient.hasOobLog(secret);
  }
}
