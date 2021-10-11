package com.google.tsunami.plugins.cve202138540;

import static com.google.common.truth.extensions.proto.ProtoTruth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostnameAndPort;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forIp;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forIpAndPort;
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
import com.google.tsunami.plugins.cve202138540.ApacheAirflowCVE202138540VulnDetector;
import com.google.tsunami.proto.AdditionalDetail;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.TransportProtocol;
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

@RunWith(JUnit4.class)
public final class ApacheAirflowCVE202138540VulnDetectorTest {
  @Rule public final TemporaryFolder tempFolder = new TemporaryFolder();
  @Rule public final MockitoRule mockito = MockitoJUnit.rule();

  // Tsunami provides several testing utilities to make your lives easier with unit test.
  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2020-01-01T00:00:00.00Z"));

  @Mock private CommandExecutor commandExecutor;
  private File commandOutputFile;
  private ApacheAirflowCVE202138540VulnDetector detector;

  @Before
  public void setUp() throws IOException, ExecutionException, InterruptedException {
    Process mockProcess = mock(Process.class, RETURNS_SMART_NULLS);
    when(commandExecutor.execute(any())).thenReturn(mockProcess);

    CommandExecutorFactory.setInstance(commandExecutor);
    commandOutputFile = tempFolder.newFile();
    detector =
        new ApacheAirflowCVE202138540VulnDetector(
            fakeUtcClock, MoreExecutors.newDirectExecutorService(), commandOutputFile);
  }

  // In Tsunami, unit test names should follow the following general convention:
  // functionUnderTest_condition_outcome.
  @Test
  public void detect_whenScriptReturnsNonEmptyYes_returnsVulnerability() throws IOException {
    Files.asCharSink(commandOutputFile, UTF_8).write("YES Apache Airflow is vulnerable to CVE-2021-38540");


    DetectionReportList detectionReports =
        detector.detect(
            TargetInfo.newBuilder().addNetworkEndpoints(forIp("0.0.0.0")).build(),
            ImmutableList.of(
                NetworkService.newBuilder()
                    .setNetworkEndpoint(forIpAndPort("0.0.0.0", 8080))
                    .setTransportProtocol(TransportProtocol.TCP)
                    .setServiceName("http")
                    .build()));

    assertThat(detectionReports.getDetectionReportsList())
        .containsExactly(
            DetectionReport.newBuilder()
                .setTargetInfo(TargetInfo.newBuilder().addNetworkEndpoints(forIp("0.0.0.0")))
                .setNetworkService(NetworkService.newBuilder()
                        .setNetworkEndpoint(forIpAndPort("0.0.0.0", 8080))
                        .setTransportProtocol(TransportProtocol.TCP)
                        .setServiceName("http")
                        .build())
                .setDetectionTimestamp(
                    Timestamps.fromMillis(Instant.now(fakeUtcClock).toEpochMilli()))
                .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
                .setVulnerability(
                     Vulnerability.newBuilder()
                        .setMainId(
                            VulnerabilityId.newBuilder()
                                .setPublisher("TSUNAMI_COMMUNITY")
                                .setValue("CVE_2021_38540"))
                        .setSeverity(Severity.CRITICAL)
                        .setTitle("Apache Airflow CVE-2021-38540: Unauthenticated Endpoint")
                        .setCvssV3("9.8")
                        .setCvssV2("7.5")
                        .setDescription("The variable import endpoint was not protected by authentication "
                         + "in Airflow >=2.0.0, <2.1.3. This allowed unauthenticated users to hit that "
                         + "endpoint to add/modify Airflow variables used in DAGs, potentially resulting"
                         + "in a denial of service, information disclosure or remote code execution. "
                         + "This issue affects Apache Airflow >=2.0.0, <2.1.3." ))
                .build());
  }

  @Test
  public void detect_whenScriptReturnsEmptyNo_returnsEmptyVulnerability() throws IOException {
    Files.asCharSink(commandOutputFile, UTF_8).write("NO Latest or very old apache airflow is running.");

    DetectionReportList detectionReports =
        detector.detect(
            TargetInfo.newBuilder().addNetworkEndpoints(forIp("0.0.0.0")).build(),
            ImmutableList.of(
                NetworkService.newBuilder()
                    .setNetworkEndpoint(forIpAndPort("0.0.0.0", 8080))
                    .setTransportProtocol(TransportProtocol.TCP)
                    .setServiceName("http")
                    .build()));

    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
  }
}
