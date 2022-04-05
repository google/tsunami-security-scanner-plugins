/*
 * Copyright 2022 Google LLC
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
package com.google.tsunami.plugins.detectors.spring;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.tsunami.common.net.http.HttpRequest.get;
import static com.google.tsunami.common.net.http.HttpRequest.post;

import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpResponse;
import com.google.tsunami.common.net.http.HttpStatus;
import com.google.tsunami.common.time.UtcClock;
import com.google.tsunami.plugin.PluginType;
import com.google.tsunami.plugin.VulnDetector;
import com.google.tsunami.plugin.annotations.PluginInfo;
import com.google.tsunami.proto.CrawlResult;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.Vulnerability;
import com.google.tsunami.proto.VulnerabilityId;
import java.io.IOException;
import java.time.Clock;
import java.time.Instant;
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
  private static final String VULNERABILITY_PAYLOAD_STRING_1 =
      "class.module.classLoader.DefaultAssertionStatus=1";
  private static final String VULNERABILITY_PAYLOAD_STRING_2 =
      "class.module.classLoader.DefaultAssertionStatus=2";

  private final Clock utcClock;
  private final HttpClient httpClient;

  @Inject
  SpringCve202222965Detector(@UtcClock Clock utcClock, HttpClient httpClient) {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient);
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

  private boolean isServiceVulnerable(NetworkService networkService) {
    if (proofOfConcept(
        NetworkServiceUtils.buildWebApplicationRootUrl(networkService), "GET", networkService)) {
      return true;
    }
    if (networkService.getServiceContext().getWebServiceContext().getCrawlResultsCount() == 0) {
      return false;
    }
    for (CrawlResult crawlResult :
        networkService.getServiceContext().getWebServiceContext().getCrawlResultsList()) {
      String targetUri = crawlResult.getCrawlTarget().getUrl();
      String httpMethod = crawlResult.getCrawlTarget().getHttpMethod();
      if (proofOfConcept(targetUri, httpMethod, networkService)) {
        return true;
      }
    }
    return false;
  }

  private boolean proofOfConcept(
      String targetUri, String httpMethod, NetworkService networkService) {
    HttpResponse firstPoCResponse;
    HttpResponse secondPoCResponse;
    try {
      switch (httpMethod) {
        case "GET":
          firstPoCResponse =
              httpClient.send(
                  get(targetUri + "?" + VULNERABILITY_PAYLOAD_STRING_1).withEmptyHeaders().build(),
                  networkService);
          secondPoCResponse =
              httpClient.send(
                  get(targetUri + "?" + VULNERABILITY_PAYLOAD_STRING_2).withEmptyHeaders().build(),
                  networkService);
          break;
        case "POST":
          firstPoCResponse =
              httpClient.send(
                  post(targetUri + "?" + VULNERABILITY_PAYLOAD_STRING_1).withEmptyHeaders().build(),
                  networkService);
          secondPoCResponse =
              httpClient.send(
                  post(targetUri + "?" + VULNERABILITY_PAYLOAD_STRING_2).withEmptyHeaders().build(),
                  networkService);
          break;
        default:
          logger.atWarning().log("Unable to query '%s'.", targetUri);
          return false;
      }
      if (firstPoCResponse.status() == HttpStatus.OK
          && secondPoCResponse.status() == HttpStatus.BAD_REQUEST) {
        return true;
      }
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Unable to query '%s'.", targetUri);
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
                        .setValue("CVE_2022_22965"))
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
                        + "upgrade to 5.2.20+."))
        .build();
  }
}
