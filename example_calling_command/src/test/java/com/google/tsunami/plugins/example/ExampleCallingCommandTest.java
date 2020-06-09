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
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.RETURNS_SMART_NULLS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.google.common.collect.ImmutableList;
import com.google.common.io.Files;
import com.google.common.util.concurrent.MoreExecutors;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.command.CommandExecutor;
import com.google.tsunami.common.command.CommandExecutorFactory;
import com.google.tsunami.common.time.testing.FakeUtcClock;
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
import java.io.File;
import java.io.IOException;
import java.time.Instant;
import java.util.concurrent.ExecutionException;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;

/** Unit tests for {@link ExampleCallingCommand}. */
@RunWith(JUnit4.class)
public final class ExampleCallingCommandTest {
  @Rule public final TemporaryFolder tempFolder = new TemporaryFolder();
  @Rule public final MockitoRule mockito = MockitoJUnit.rule();

  // Tsunami provides several testing utilities to make your lives easier with unit test.
  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2020-01-01T00:00:00.00Z"));

  @Mock private CommandExecutor commandExecutor;
  private File commandOutputFile;
  private ExampleCallingCommand detector;

  @Before
  public void setUp() throws IOException, ExecutionException, InterruptedException {
    Process mockProcess = mock(Process.class, RETURNS_SMART_NULLS);
    when(commandExecutor.execute(any())).thenReturn(mockProcess);

    CommandExecutorFactory.setInstance(commandExecutor);
    commandOutputFile = tempFolder.newFile();
    detector =
        new ExampleCallingCommand(
            fakeUtcClock, MoreExecutors.newDirectExecutorService(), commandOutputFile);
  }

  // In Tsunami, unit test names should follow the following general convention:
  // functionUnderTest_condition_outcome.
  @Test
  public void detect_whenScriptReturnsNonEmpty_returnsVulnerability() throws IOException {
    Files.asCharSink(commandOutputFile, UTF_8).write("script output");

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

  @Test
  public void detect_whenScriptReturnsEmpty_returnsEmptyVulnerability() throws IOException {
    Files.asCharSink(commandOutputFile, UTF_8).write("");

    DetectionReportList detectionReports =
        detector.detect(
            TargetInfo.getDefaultInstance(), ImmutableList.of(NetworkService.getDefaultInstance()));

    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
  }
}
