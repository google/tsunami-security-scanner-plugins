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
package com.google.tsunami.plugins.detectors.rce.rsync;

import static com.google.common.truth.extensions.proto.ProtoTruth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forIpAndPort;

import com.google.common.collect.ImmutableList;
import com.google.inject.Guice;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.common.time.testing.FakeUtcClockModule;
import com.google.tsunami.proto.AdditionalDetail;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.TextData;
import com.google.tsunami.proto.TransportProtocol;
import java.time.Instant;
import javax.inject.Inject;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link RsyncRceDetector}. */
@RunWith(JUnit4.class)
public final class RsyncRceDetectorTest {
  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2020-01-01T00:00:00.00Z"));

  @Inject private RsyncRceDetector detector;

  @Before
  public void setUp() {
    Guice.createInjector(new FakeUtcClockModule(fakeUtcClock)).injectMembers(this);
  }

  @Test
  public void detect_whenNonRsyncService_ignore() {
    var nonRsyncServices =
        ImmutableList.of(
            NetworkService.newBuilder().setServiceName("ssh").build(),
            NetworkService.newBuilder().setServiceName("rdp").build());

    assertThat(
            detector
                .detect(TargetInfo.getDefaultInstance(), nonRsyncServices)
                .getDetectionReportsList())
        .isEmpty();
  }

  @Test
  public void detect_whenEmptyRsyncBanner_emptyDetectionReport() {
    var rsyncService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(forIpAndPort("127.0.0.1", 873))
            .setServiceName("rsync")
            .setTransportProtocol(TransportProtocol.TCP)
            .build();

    assertThat(
            detector
                .detect(TargetInfo.getDefaultInstance(), ImmutableList.of(rsyncService))
                .getDetectionReportsList())
        .isEmpty();
  }

  @Test
  public void detect_whenNonVulnerableBanner_emptyDetectionReport() {
    var rsyncService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(forIpAndPort("127.0.0.1", 873))
            .setServiceName("rsync")
            .setTransportProtocol(TransportProtocol.TCP)
            .addBanner("@RSYNCD: 31.0")
            .build();

    assertThat(
            detector
                .detect(TargetInfo.getDefaultInstance(), ImmutableList.of(rsyncService))
                .getDetectionReportsList())
        .isEmpty();
  }

  @Test
  public void detect_whenVulnerableBanner_returnsDetection() {
    var vulnerableBanner = "@RSYNCD: 31.0 sha512 sha256 sha1 md5 md4";
    var rsyncService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(forIpAndPort("127.0.0.1", 873))
            .setServiceName("rsync")
            .setTransportProtocol(TransportProtocol.TCP)
            .addBanner(vulnerableBanner)
            .build();

    assertThat(
            detector
                .detect(TargetInfo.getDefaultInstance(), ImmutableList.of(rsyncService))
                .getDetectionReportsList())
        .containsExactly(
            DetectionReport.newBuilder()
                .setTargetInfo(TargetInfo.getDefaultInstance())
                .setNetworkService(rsyncService)
                .setDetectionTimestamp(Timestamps.fromMillis(fakeUtcClock.instant().toEpochMilli()))
                .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
                .setVulnerability(
                    detector.getAdvisory(
                        AdditionalDetail.newBuilder()
                            .setDescription("Rsync banner")
                            .setTextData(TextData.newBuilder().setText(vulnerableBanner))
                            .build()))
                .build());
  }

  @Test
  public void detect_whenNonVulnerableProtocolVersionInBanner_emptyDetectionReport() {
    var rsyncService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(forIpAndPort("127.0.0.1", 873))
            .setServiceName("rsync")
            .setTransportProtocol(TransportProtocol.TCP)
            .addBanner("@RSYNCD: 32.0 sha512 sha256 sha1 md5 md4")
            .build();

    assertThat(
            detector
                .detect(TargetInfo.getDefaultInstance(), ImmutableList.of(rsyncService))
                .getDetectionReportsList())
        .isEmpty();
  }
}
