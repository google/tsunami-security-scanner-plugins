package com.google.tsunami.plugins.detectors.templateddetector;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;

import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.time.UtcClock;
import com.google.tsunami.plugin.PluginType;
import com.google.tsunami.plugin.TcsClient;
import com.google.tsunami.plugin.VulnDetector;
import com.google.tsunami.plugin.annotations.PluginInfo;
import com.google.tsunami.plugin.payload.PayloadSecretGenerator;
import com.google.tsunami.plugins.detectors.templateddetector.actions.CallbackServerActionRunner;
import com.google.tsunami.plugins.detectors.templateddetector.actions.HttpActionRunner;
import com.google.tsunami.plugins.detectors.templateddetector.actions.UtilityActionRunner;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.templatedplugin.proto.PluginAction;
import com.google.tsunami.templatedplugin.proto.PluginWorkflow;
import com.google.tsunami.templatedplugin.proto.TemplatedPlugin;
import java.time.Clock;
import java.util.HashMap;
import javax.inject.Inject;

/** TemplatedDetector is a vulnerability detector that runs templated plugins. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "",
    version = "",
    description = "",
    author = "",
    bootstrapModule = TemplatedDetectorBootstrapModule.class)
public final class TemplatedDetector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  private final TemplatedPlugin proto;
  private final HashMap<String, PluginAction> actionsCache;

  private HttpClient httpClient = null;
  private TcsClient tcsClient = null;
  private Clock utcClock = null;
  private PayloadSecretGenerator secretGenerator = null;

  public TemplatedDetector(TemplatedPlugin proto) {
    this.proto = proto;
    this.actionsCache = new HashMap<>();
  }

  public String getName() {
    return this.proto.getInfo().getName();
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("Starting detector: %s", this.proto.getInfo().getName());
    // Cache the action names.
    for (PluginAction action : this.proto.getActionsList()) {
      this.actionsCache.put(action.getName(), action);
    }

    // Find the first workflow that matches the current conditions.
    for (PluginWorkflow workflow : this.proto.getWorkflowsList()) {
      if (workflowMeetsConditions(workflow)) {
        return useWorkflow(targetInfo, matchedServices, workflow);
      }
    }

    logger.atSevere().log(
        "No workflow matched the current setup. Is plugin '%s' misconfigured?",
        this.proto.getInfo().getName());
    return DetectionReportList.getDefaultInstance();
  }

  @Inject
  void setHttpClient(HttpClient httpClient) {
    this.httpClient = checkNotNull(httpClient);
  }

  @Inject
  void setTcsClient(TcsClient tcsClient) {
    this.tcsClient = checkNotNull(tcsClient);
  }

  @Inject
  void setUtcClock(@UtcClock Clock utcClock) {
    this.utcClock = checkNotNull(utcClock);
  }

  @Inject
  void setPayloadSecretGenerator(PayloadSecretGenerator secretGenerator) {
    this.secretGenerator = checkNotNull(secretGenerator);
  }

  private final boolean workflowMeetsConditions(PluginWorkflow workflow) {
    switch (workflow.getCondition()) {
      case REQUIRES_CALLBACK_SERVER:
        return tcsClient.isCallbackServerEnabled();
      default:
        return true;
    }
  }

  private final ActionRunner getRunnerForAction(PluginAction action) {
    switch (action.getAnyActionCase()) {
      case HTTP_REQUEST:
        return new HttpActionRunner(this.httpClient, this.proto.getConfig().getDebug());
      case CALLBACK_SERVER:
        return new CallbackServerActionRunner(this.tcsClient, this.proto.getConfig().getDebug());
      case UTILITY:
        return new UtilityActionRunner();
      default:
        throw new IllegalArgumentException(
            String.format("Unsupported action type: %s", action.getAnyActionCase()));
    }
  }

  private final boolean dispatchAction(
      NetworkService service, PluginAction action, Environment environment) {
    // if the action type is HTTP, we need to ensure that we are dealing with an HTTP-aware service.
    if (action.getAnyActionCase() == PluginAction.AnyActionCase.HTTP_REQUEST) {
      if (!NetworkServiceUtils.isWebService(service)) {
        logger.atInfo().log(
            "Service on port %d is not a web service, skipping action '%s'",
            service.getNetworkEndpoint().getPort().getPortNumber(), action.getName());
        return false;
      }
    }

    return getRunnerForAction(action).run(service, action, environment);
  }

  // note: expect action names to have been validated already
  private final boolean runWorkflowForService(NetworkService service, PluginWorkflow workflow) {
    // We prepare a new environment for that workflow.
    Environment environment = new Environment(this.proto.getConfig().getDebug(), this.utcClock);
    environment.initializeFor(service, this.tcsClient, this.secretGenerator);

    for (var parameter : workflow.getVariablesList()) {
      var value = environment.substitute(parameter.getValue());
      environment.set(parameter.getName(), value);
    }

    // Run every individual action and inventorize clean up actions.
    boolean success = true;
    ImmutableList.Builder<String> cleanupActionsBuilder = ImmutableList.builder();
    for (String actionName : workflow.getActionsList()) {
      PluginAction action = this.actionsCache.get(actionName);
      if (!dispatchAction(service, action, environment)) {
        logger.atInfo().log("No vulnerability found because action '%s' failed.", actionName);
        success = false;
        break;
      }

      cleanupActionsBuilder.addAll(action.getCleanupActionsList());
    }

    var cleanupActions = cleanupActionsBuilder.build();
    if (cleanupActions.isEmpty()) {
      return success;
    }

    // Run all the clean up actions that were registered.
    logger.atInfo().log("Running %d cleanup action(s)", cleanupActions.size());
    for (String cleanupActionName : cleanupActions) {
      PluginAction cleanupAction = this.actionsCache.get(cleanupActionName);
      if (!dispatchAction(service, cleanupAction, environment)) {
        logger.atWarning().log(
            "Cleanup action '%s' failed: manual clean up of service on port %d might be needed",
            cleanupActionName, service.getNetworkEndpoint().getPort().getPortNumber());
      }
    }

    return success;
  }

  private final DetectionReportList useWorkflow(
      TargetInfo targetInfo,
      ImmutableList<NetworkService> matchedService,
      PluginWorkflow workflow) {
    // First we check that all registered actions exists.
    for (String actionName : workflow.getActionsList()) {
      if (!this.actionsCache.containsKey(actionName)) {
        throw new IllegalArgumentException(
            String.format("Plugin definition error: action '%s' not found.", actionName));
      }
    }

    // Also check that all registered cleanups are valid.
    for (PluginAction action : this.actionsCache.values()) {
      for (String cleanupActionName : action.getCleanupActionsList()) {
        if (!this.actionsCache.containsKey(cleanupActionName)) {
          throw new IllegalArgumentException(
              String.format(
                  "Plugin definition error: cleanup action '%s' defined in action '%s' not found.",
                  cleanupActionName, action.getName()));
        }
      }
    }

    return DetectionReportList.newBuilder()
        .addAllDetectionReports(
            matchedService.stream()
                .filter(service -> runWorkflowForService(service, workflow))
                .peek(
                    service ->
                        logger.atInfo().log(
                            "Vulnerability found on port %d with plugin '%s'",
                            service.getNetworkEndpoint().getPort().getPortNumber(),
                            this.proto.getInfo().getName()))
                .map(service -> buildDetectionReport(targetInfo, service))
                .collect(toImmutableList()))
        .build();
  }

  private DetectionReport buildDetectionReport(
      TargetInfo targetInfo, NetworkService vulnerableNetworkService) {
    return DetectionReport.newBuilder()
        .setTargetInfo(targetInfo)
        .setNetworkService(vulnerableNetworkService)
        .setDetectionTimestamp(Timestamps.fromMillis(utcClock.instant().toEpochMilli()))
        .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
        .setVulnerability(this.proto.getFinding())
        .build();
  }
}
