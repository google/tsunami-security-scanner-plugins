package com.google.tsunami.plugins.detectors.templateddetector.actions;

import com.google.common.flogger.GoogleLogger;
import com.google.tsunami.plugins.detectors.templateddetector.ActionRunner;
import com.google.tsunami.plugins.detectors.templateddetector.Environment;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.templatedplugin.proto.PluginAction;
import com.google.tsunami.templatedplugin.proto.UtilityAction;

/** CallbackServerActionRunner is an ActionRunner that runs utility actions. */
public final class UtilityActionRunner implements ActionRunner {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  public UtilityActionRunner() {}

  @Override
  public boolean run(NetworkService service, PluginAction action, Environment environment) {
    var utility = action.getUtility();
    var actionType = utility.getActionCase();

    switch (actionType) {
      case SLEEP:
        return performActionSleep(utility);
      default:
        logger.atSevere().log("Unknown utility type: %s", actionType);
        return false;
    }
  }

  private boolean performActionSleep(UtilityAction action) {
    var sleepAction = action.getSleep();
    var duration = sleepAction.getDurationMs();

    logger.atInfo().log("Sleeping for %s ms", duration);

    try {
      Thread.sleep(duration);
    } catch (InterruptedException e) {
      logger.atSevere().withCause(e).log("Failed to sleep");
      return false;
    }

    return true;
  }
}
