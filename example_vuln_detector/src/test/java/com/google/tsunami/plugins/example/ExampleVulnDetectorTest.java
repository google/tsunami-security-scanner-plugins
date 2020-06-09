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
package com.google.tsunami.plugins.example;

import static com.google.common.truth.extensions.proto.ProtoTruth.assertThat;

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

/** Unit tests for {@link ExampleVulnDetector}. */
@RunWith(JUnit4.class)
public final class ExampleVulnDetectorTest {
  // Tsunami provides several testing utilities to make your lives easier with unit test.
  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2020-01-01T00:00:00.00Z"));

  @Inject private ExampleVulnDetector detector;

  @Before
  public void setUp() {
    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock), new ExampleVulnDetectorBootstrapModule())
        .injectMembers(this);
  }

  // In Tsunami, unit test names should follow the following general convention:
  // functionUnderTest_condition_outcome.
  @Test
  public void detect_always_returnsVulnerability() {
    DetectionReportList detectionReports =
        detector.detect(
            TargetInfo.getDefaultInstance(), ImmutableList.of(NetworkService.getDefaultInstance()));

    assertThat(detectionReports.getDetectionReportsList())
        .containsExactly(
            DetectionReport.newBuilder()
                .setTargetInfo(TargetInfo.getDefaultInstance())
                .setNetworkService(NetworkService.getDefaultInstance())
                .setDetectionTimestamp(
                    Timestamps.fromMillis(Instant.now(fakeUtcClock).toEpochMilli()))
                .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
                .setVulnerability(
                    Vulnerability.newBuilder()
                        .setMainId(
                            VulnerabilityId.newBuilder()
                                .setPublisher("vulnerability_id_publisher")
                                .setValue("VULNERABILITY_ID"))
                        .setSeverity(Severity.CRITICAL)
                        .setTitle("Vulnerability Title")
                        .setDescription("Detailed description of the vulnerability")
                        .addAdditionalDetails(
                            AdditionalDetail.newBuilder()
                                .setTextData(
                                    TextData.newBuilder()
                                        .setText("Some additional technical details."))))
                .build());
  }
}
