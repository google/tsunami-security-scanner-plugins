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
package com.google.tsunami.plugins.detectors.rce.cve20246387;

import static com.google.common.truth.extensions.proto.ProtoTruth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostnameAndPort;
import static com.google.tsunami.plugins.detectors.rce.cve20246387.Cve20246387Detector.DESCRIPTION;
import static com.google.tsunami.plugins.detectors.rce.cve20246387.Cve20246387Detector.RECOMMENDATION;
import static com.google.tsunami.plugins.detectors.rce.cve20246387.Cve20246387Detector.TITLE;

import com.google.common.collect.ImmutableList;
import com.google.inject.Guice;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.common.time.testing.FakeUtcClockModule;
import com.google.tsunami.proto.AdditionalDetail;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.TextData;
import com.google.tsunami.proto.Vulnerability;
import com.google.tsunami.proto.VulnerabilityId;
import java.time.Instant;
import javax.inject.Inject;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link Cve20246387Detector} */
@RunWith(JUnit4.class)
public final class Cve20246387DetectorTest {
  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2020-01-01T00:00:00.00Z"));

  @Inject Cve20246387Detector detector;

  @Before
  public void setUp() {
    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock), new Cve20246387DetectorBootstrapModule())
        .injectMembers(this);
  }

  @Test
  public void detect_noBanner_returnsEmpty() {
    var targetNetworkService =
        NetworkService.newBuilder().setNetworkEndpoint(forHostnameAndPort("localhost", 22)).build();
    var targetInfo =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(targetNetworkService.getNetworkEndpoint())
            .build();

    DetectionReportList detectionReports =
        detector.detect(targetInfo, ImmutableList.of(targetNetworkService));

    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
  }

  @Test
  public void detect_nonSshBanner_returnsEmpty() {
    var targetNetworkService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(forHostnameAndPort("localhost", 22))
            .addBanner("irrelevant")
            .build();
    var targetInfo =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(targetNetworkService.getNetworkEndpoint())
            .build();

    DetectionReportList detectionReports =
        detector.detect(targetInfo, ImmutableList.of(targetNetworkService));

    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
  }

  @Test
  public void detect_nonVulnerableSshBanner_returnsNoFinding() {
    var targetNetworkService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(forHostnameAndPort("localhost", 22))
            .addBanner("\n\nSSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u3")
            .build();
    var targetInfo =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(targetNetworkService.getNetworkEndpoint())
            .build();

    DetectionReportList detectionReports =
        detector.detect(targetInfo, ImmutableList.of(targetNetworkService));

    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
  }

  @Test
  public void detect_nonVulnerableGenericSshBanner_returnsNoFinding() {
    var targetNetworkService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(forHostnameAndPort("localhost", 22))
            .addBanner("\n\nSSH-2.0-OpenSSH_8.0")
            .build();
    var targetInfo =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(targetNetworkService.getNetworkEndpoint())
            .build();

    DetectionReportList detectionReports =
        detector.detect(targetInfo, ImmutableList.of(targetNetworkService));

    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
  }

  @Test
  public void detect_vulnerableSshBanner_returnsVulnerability() {
    var targetNetworkService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(forHostnameAndPort("localhost", 22))
            .addBanner("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13")
            .build();
    var targetInfo =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(targetNetworkService.getNetworkEndpoint())
            .build();

    DetectionReportList detectionReports =
        detector.detect(targetInfo, ImmutableList.of(targetNetworkService));

    assertThat(detectionReports.getDetectionReportsList())
        .containsExactly(
            DetectionReport.newBuilder()
                .setTargetInfo(targetInfo)
                .setNetworkService(targetNetworkService)
                .setDetectionTimestamp(Timestamps.fromMillis(fakeUtcClock.millis()))
                .setDetectionStatus(DetectionStatus.VULNERABILITY_PRESENT)
                .setVulnerability(
                    Vulnerability.newBuilder()
                        .setMainId(
                            VulnerabilityId.newBuilder()
                                .setPublisher("GOOGLE")
                                .setValue("CVE-2024-6387"))
                        .addRelatedId(
                            VulnerabilityId.newBuilder()
                                .setPublisher("CVE")
                                .setValue("CVE-2024-6387"))
                        .setSeverity(Severity.CRITICAL)
                        .setTitle(TITLE)
                        .setDescription(DESCRIPTION)
                        .setRecommendation(RECOMMENDATION)
                        .addAdditionalDetails(
                            AdditionalDetail.newBuilder()
                                .setTextData(
                                    TextData.newBuilder()
                                        .setText("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13"))
                                .build()))
                .build());
  }
}
