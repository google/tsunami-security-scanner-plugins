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
package com.google.tsunami.plugins.detectors.rce.kubernetes;

import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostnameAndPort;

import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.proto.AdditionalDetail;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkEndpoint;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.Software;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.TextData;
import com.google.tsunami.proto.TransportProtocol;
import com.google.tsunami.proto.Vulnerability;
import com.google.tsunami.proto.VulnerabilityId;
import java.time.Instant;
import okhttp3.mockwebserver.MockWebServer;

/** Helper class for shared methods in this test suite */
final class TestHelper {

  private TestHelper() {}

  static NetworkService createKubernetesService(MockWebServer mockService) {
    return NetworkService.newBuilder()
        .setNetworkEndpoint(forHostnameAndPort(mockService.getHostName(), mockService.getPort()))
        .setTransportProtocol(TransportProtocol.TCP)
        .setSoftware(Software.newBuilder().setName("Kubernetes API"))
        .setServiceName("http")
        .build();
  }

  static TargetInfo buildTargetInfo(NetworkEndpoint networkEndpoint) {
    return TargetInfo.newBuilder().addNetworkEndpoints(networkEndpoint).build();
  }

  static DetectionReport buildValidDetectionReportHigh(
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
                        .setPublisher(
                            RCEInKubernetesClusterWithOpenAccessDetector
                                .VULNERABILITY_REPORT_PUBLISHER)
                        .setValue(
                            RCEInKubernetesClusterWithOpenAccessDetector.VULNERABILITY_REPORT_ID))
                .setSeverity(Severity.HIGH)
                .setTitle(RCEInKubernetesClusterWithOpenAccessDetector.VULNERABILITY_REPORT_TITLE)
                .setDescription(
                    RCEInKubernetesClusterWithOpenAccessDetector.VULNERABILITY_REPORT_DESCRIPTION)
                .setRecommendation(
                    RCEInKubernetesClusterWithOpenAccessDetector
                        .VULNERABILITY_REPORT_RECOMMENDATION)
                .addAdditionalDetails(
                    AdditionalDetail.newBuilder()
                        .setTextData(
                            TextData.newBuilder()
                                .setText(
                                    RCEInKubernetesClusterWithOpenAccessDetector
                                        .VULNERABILITY_REPORT_DETAILS))))
        .build();
  }

  static DetectionReport buildValidDetectionReportCritical(
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
                        .setPublisher(
                            RCEInKubernetesClusterWithOpenAccessDetector
                                .VULNERABILITY_REPORT_PUBLISHER)
                        .setValue(
                            RCEInKubernetesClusterWithOpenAccessDetector.VULNERABILITY_REPORT_ID))
                .setSeverity(Severity.CRITICAL)
                .setTitle(RCEInKubernetesClusterWithOpenAccessDetector.VULNERABILITY_REPORT_TITLE)
                .setDescription(
                    RCEInKubernetesClusterWithOpenAccessDetector.VULNERABILITY_REPORT_DESCRIPTION)
                .setRecommendation(
                    RCEInKubernetesClusterWithOpenAccessDetector
                        .VULNERABILITY_REPORT_RECOMMENDATION)
                .addAdditionalDetails(
                    AdditionalDetail.newBuilder()
                        .setTextData(
                            TextData.newBuilder()
                                .setText(
                                    RCEInKubernetesClusterWithOpenAccessDetector
                                        .VULNERABILITY_REPORT_DETAILS))))
        .build();
  }
}
