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
package com.google.tsunami.plugins.detectors.rce.cve202226133;

import static com.google.tsunami.common.data.NetworkEndpointUtils.forIpAndPort;

import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.TransportProtocol;
import com.google.tsunami.proto.Vulnerability;
import com.google.tsunami.proto.VulnerabilityId;
import java.time.Instant;

final class TestHelper {
  static final byte[] CLUSTER_NAME =
      new byte[] {
        0, 0, 0, 17, 98, 105, 116, 98, 117, 99, 107, 101, 116, 45, 99, 108, 117, 115, 116, 101, 114
      };

  static TargetInfo targetInfo() {
    return TargetInfo.newBuilder().addNetworkEndpoints(forIpAndPort("127.0.0.1", 5701)).build();
  }

  static NetworkService bitbucketClusterService() {
    return NetworkService.newBuilder()
        .setNetworkEndpoint(forIpAndPort("127.0.0.1", 5701))
        .setTransportProtocol(TransportProtocol.TCP)
        .setServiceName("unknown")
        .build();
  }

  static DetectionReport buildValidDetectionReport(
      TargetInfo targetInfo, NetworkService service, FakeUtcClock fakeUtcClock) {
    return DetectionReport.newBuilder()
        .setTargetInfo(targetInfo())
        .setNetworkService(bitbucketClusterService())
        .setDetectionTimestamp(Timestamps.fromMillis(Instant.now(fakeUtcClock).toEpochMilli()))
        .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
        .setVulnerability(
            Vulnerability.newBuilder()
                .setMainId(
                    VulnerabilityId.newBuilder()
                        .setPublisher("TSUNAMI_COMMUNITY")
                        .setValue("CVE_2022_26133"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("Atlassian Bitbucket DC RCE (CVE-2022-26133)")
                .setDescription(
                    "SharedSecretClusterAuthenticator in Atlassian Bitbucket Data Center versions"
                        + " 5.14.0 and later before 7.6.14, 7.7.0 and later prior to 7.17.6,"
                        + " 7.18.0 and later prior to 7.18.4, 7.19.0 and later prior"
                        + " to 7.19.4, and 7.20.0 allow a remote, unauthenticated attacker to "
                        + "execute arbitrary code via Java deserialization."))
        .build();
  }

  private TestHelper() {}
}
