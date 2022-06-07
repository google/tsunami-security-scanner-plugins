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

package com.google.tsunami.plugins.detectors.rce.cve202226134;

import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostnameAndPort;
import static com.google.tsunami.plugins.detectors.rce.cve202226134.ConfluenceOgnlInjectionRceDetector.RECOMMENDATION;
import static com.google.tsunami.plugins.detectors.rce.cve202226134.ConfluenceOgnlInjectionRceDetector.VULNERABILITY_REPORT_ID;
import static com.google.tsunami.plugins.detectors.rce.cve202226134.ConfluenceOgnlInjectionRceDetector.VULNERABILITY_REPORT_PUBLISHER;
import static com.google.tsunami.plugins.detectors.rce.cve202226134.ConfluenceOgnlInjectionRceDetector.VULNERABILITY_REPORT_TITLE;
import static com.google.tsunami.plugins.detectors.rce.cve202226134.ConfluenceOgnlInjectionRceDetector.VULN_DESCRIPTION;

import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkEndpoint;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.TransportProtocol;
import com.google.tsunami.proto.Vulnerability;
import com.google.tsunami.proto.VulnerabilityId;
import java.time.Instant;
import okhttp3.mockwebserver.MockWebServer;

final class TestHelper {
  private TestHelper() {}

  static NetworkService createConfluenceService(MockWebServer mockService) {
    return NetworkService.newBuilder()
        .setNetworkEndpoint(forHostnameAndPort(mockService.getHostName(), mockService.getPort()))
        .setTransportProtocol(TransportProtocol.TCP)
        .setServiceName("http")
        .build();
  }

  static TargetInfo buildTargetInfo(NetworkEndpoint networkEndpoint) {
    return TargetInfo.newBuilder().addNetworkEndpoints(networkEndpoint).build();
  }

  static DetectionReport buildValidDetectionReport(
      TargetInfo target, NetworkService service, FakeUtcClock fakeUtcClock) {
    return DetectionReport.newBuilder()
        .setTargetInfo(target)
        .setNetworkService(service)
        .setDetectionTimestamp(Timestamps.fromMillis(Instant.now(fakeUtcClock).toEpochMilli()))
        .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
        .setVulnerability(
            Vulnerability.newBuilder()
                .setMainId(
                    VulnerabilityId.newBuilder()
                        .setPublisher(VULNERABILITY_REPORT_PUBLISHER)
                        .setValue(VULNERABILITY_REPORT_ID))
                .setSeverity(Severity.CRITICAL)
                .setTitle(VULNERABILITY_REPORT_TITLE)
                .setDescription(VULN_DESCRIPTION)
                .setRecommendation(RECOMMENDATION))
        .build();
  }
}
