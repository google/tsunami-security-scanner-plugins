package com.google.tsunami.plugins.detectors.templateddetector;

import com.google.common.flogger.GoogleLogger;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.plugin.TcsClient;
import com.google.tsunami.plugin.payload.PayloadSecretGenerator;
import com.google.tsunami.proto.NetworkService;
import java.time.Clock;
import java.util.HashMap;
import java.util.regex.Pattern;

/**
 * Environment stores variables that are used by the templated detector. It is a simple map of key
 * and value pairs.
 */
public final class Environment {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  private static final Pattern VARIABLE_PATTERN = Pattern.compile("\\{\\{ ([a-zA-Z0-9_]+) \\}\\}");
  private static final int SECRET_LENGTH = 8;
  private final HashMap<String, String> environment;
  private final boolean debug;
  private final Clock utcClock;

  public Environment(boolean debug, Clock utcClock) {
    this.environment = new HashMap<>();
    this.debug = debug;
    this.utcClock = utcClock;
  }

  public void initializeFor(
      NetworkService networkService, TcsClient tcsClient, PayloadSecretGenerator secretGenerator) {
    this.set("T_UTL_CURRENT_TIMESTAMP_MS", String.valueOf(utcClock.instant().toEpochMilli()));
    this.set("T_NS_BASEURL", NetworkServiceUtils.buildWebApplicationRootUrl(networkService));
    this.set("T_NS_PROTOCOL", networkService.getTransportProtocol().toString().trim());

    var endpoint = networkService.getNetworkEndpoint();
    this.set("T_NS_HOSTNAME", endpoint.getHostname().getName().trim());
    this.set("T_NS_PORT", String.valueOf(endpoint.getPort().getPortNumber()));
    this.set("T_NS_IP", endpoint.getIpAddress().getAddress().trim());

    if (secretGenerator != null) {
      var secret = secretGenerator.generate(SECRET_LENGTH);
      this.set("T_CBS_SECRET", secret);

      if (tcsClient != null && tcsClient.isCallbackServerEnabled()) {
        this.set("T_CBS_URI", tcsClient.getCallbackUri(secret));
        this.set("T_CBS_ADDRESS", tcsClient.getCallbackAddress());
        this.set("T_CBS_PORT", String.valueOf(tcsClient.getCallbackPort()));
      }
    }

    if (debug) {
      for (var entry : this.environment.entrySet()) {
        logger.atInfo().log("Environment: %s = %s", entry.getKey(), entry.getValue());
      }
    }
  }

  public void set(String key, String value) {
    this.environment.put(key, value);
  }

  public String get(String key) {
    return this.environment.get(key);
  }

  public String substitute(String template) {
    var matcher = VARIABLE_PATTERN.matcher(template);

    while (matcher.find()) {
      String variable = matcher.group(1);

      if (!this.environment.containsKey(variable)) {
        // If the variable is not found, we simply warn about it and continue.
        // We do not want to be more strict here: this implementation allows us to ignore the case
        // where `{{}}` is actually required in the payload. The drawback is that it makes debugging
        // slightly more difficult.
        logger.atWarning().log("Substitution not found for '%s' in environment", variable);
        continue;
      }

      template = template.replace(matcher.group(), this.environment.get(variable));
    }

    return template;
  }

  // Performs regexp extraction of pattern in content. Pattern must contain exactly one capturing
  // group. The resulting varname is then added to the current environment.
  // Returns true if the extraction was successful.
  public boolean extract(String content, String varname, String pattern) {
    var matcher = Pattern.compile(pattern).matcher(content);
    var found = matcher.find();

    if (!found) {
      logger.atWarning().log("Failed to extract variable '%s' from body", varname);
      return false;
    }

    this.environment.put(varname, matcher.group(1));
    return true;
  }
}
