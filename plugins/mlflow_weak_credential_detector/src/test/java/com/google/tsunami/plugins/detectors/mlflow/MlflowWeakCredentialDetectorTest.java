package com.google.tsunami.plugins.detectors.mlflow;

import static com.google.common.truth.Truth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostnameAndPort;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.google.common.collect.ImmutableList;
import com.google.inject.Guice;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpRequest;
import com.google.tsunami.common.net.http.HttpResponse;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.common.time.testing.FakeUtcClockModule;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.TransportProtocol;
import com.google.tsunami.proto.NetworkEndpoint;
import java.io.IOException;
import java.time.Instant;
import javax.inject.Inject;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.AdditionalMatchers;

@RunWith(JUnit4.class)
public class MlflowWeakCredentialDetectorTest {

  private FakeUtcClock fakeUtcClock;
  private HttpClient mockHttpClient;

  @Inject private MlflowWeakCredentialDetector detector;

  private static final String DEFAULT_USERNAME = "admin";
  private static final String DEFAULT_PASSWORD = "password";

  @Before
  public void setUp() {
    fakeUtcClock = FakeUtcClock.create();
    mockHttpClient = mock(HttpClient.class);

    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new MlflowWeakCredentialDetectorBootstrapModule(),
            binder -> {
              binder.bind(HttpClient.class).toInstance(mockHttpClient);
            })
        .injectMembers(this);
  }

  private TargetInfo buildTargetInfo(NetworkService networkService) {
    return TargetInfo.newBuilder().addNetworkEndpoints(networkService.getNetworkEndpoint()).build();
  }

  private NetworkService buildNetworkService(int port, String softwareName, TransportProtocol transportProtocol) {
    return NetworkService.newBuilder()
        .setNetworkEndpoint(forHostnameAndPort("localhost", port))
        .setTransportProtocol(transportProtocol)
        .setServiceName("http") // Assume http for web services
        .setSoftware(com.google.tsunami.proto.Software.newBuilder().setName(softwareName))
        .build();
  }
   private NetworkService buildWebService(int port) {
    return buildNetworkService(port, "mlflow", TransportProtocol.TCP);
  }

  private NetworkService buildNonWebService(int port) {
     return NetworkService.newBuilder()
        .setNetworkEndpoint(forHostnameAndPort("localhost", port))
        .setTransportProtocol(TransportProtocol.TCP)
        .setServiceName("ssh") // Example non-http service
        .build();
  }


  @Test
  public void detect_whenVulnerableMlflowService_returnsDetectionReport() throws IOException {
    NetworkService mlflowService = buildWebService(5000);
    TargetInfo targetInfo = buildTargetInfo(mlflowService);

    HttpResponse mockHttpResponse = mock(HttpResponse.class);
    when(mockHttpResponse.status()).thenReturn(com.google.tsunami.common.net.http.HttpStatus.OK);
    // Mock response body if detector logic starts using it for verification
    // when(mockHttpResponse.bodyBytes()).thenReturn(Optional.of("MLflow UI".getBytes(UTF_8)));

    when(mockHttpClient.send(
            AdditionalMatchers.and(
                HttpRequest.get("http://localhost:5000/api/2.0/mlflow/experiments/list").build(),
                HttpRequest.get("http://localhost:5000/api/2.0/mlflow/experiments/list")
                    .withCredentials(DEFAULT_USERNAME, DEFAULT_PASSWORD)
                    .build()),
            any(NetworkService.class)))
        .thenReturn(mockHttpResponse);

    fakeUtcClock.setNow(Instant.parse("2020-01-01T00:00:00.00Z"));

    DetectionReportList detectionReports =
        detector.detect(targetInfo, ImmutableList.of(mlflowService));

    assertThat(detectionReports.getDetectionReportsList()).hasSize(1);
    DetectionReport report = detectionReports.getDetectionReports(0);
    assertThat(report.getTargetInfo()).isEqualTo(targetInfo);
    assertThat(report.getNetworkService()).isEqualTo(mlflowService);
    assertThat(report.getDetectionStatus()).isEqualTo(DetectionStatus.VULNERABILITY_VERIFIED);
    assertThat(report.getVulnerability().getMainId().getValue()).isEqualTo("MLFLOW_WEAK_CREDENTIAL");
    assertThat(report.getVulnerability().getSeverity()).isEqualTo(Severity.CRITICAL);
    assertThat(report.getVulnerability().getTitle()).isEqualTo("MLflow Default Weak Credentials");
    assertThat(report.getVulnerability().getDescription())
        .contains("username: 'admin', password: 'password'");
    assertThat(report.getVulnerability().getCvssV3()).isEqualTo("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  }

  @Test
  public void detect_whenMlflowAuthEnabledButNotDefaultCreds_returnsNoReport() throws IOException {
    NetworkService mlflowService = buildWebService(5000);
    TargetInfo targetInfo = buildTargetInfo(mlflowService);

    HttpResponse mockHttpResponse = mock(HttpResponse.class);
    when(mockHttpResponse.status()).thenReturn(com.google.tsunami.common.net.http.HttpStatus.UNAUTHORIZED);

    when(mockHttpClient.send(
            any(HttpRequest.class), // More lenient matching for this case
            any(NetworkService.class)))
        .thenReturn(mockHttpResponse);

    DetectionReportList detectionReports =
        detector.detect(targetInfo, ImmutableList.of(mlflowService));

    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
  }

  @Test
  public void detect_whenMlflowAuthNotEnabledOrNotMlflow_returnsNoReport() throws IOException {
    // Simulate a service that returns 200 OK without any auth, or a non-MLflow service
    NetworkService otherWebService = buildWebService(8080);
    TargetInfo targetInfo = buildTargetInfo(otherWebService);

    HttpResponse mockHttpResponse = mock(HttpResponse.class);
    // For example, a 302 redirect, or a 200 OK that's not an MLflow authenticated page
    // The current detector logic treats any non-200 (for default creds) and non-401/403 as "not vulnerable"
    when(mockHttpResponse.status()).thenReturn(com.google.tsunami.common.net.http.HttpStatus.FOUND);

    when(mockHttpClient.send(any(HttpRequest.class), any(NetworkService.class)))
        .thenReturn(mockHttpResponse);

    DetectionReportList detectionReports =
        detector.detect(targetInfo, ImmutableList.of(otherWebService));

    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
  }


  @Test
  public void detect_whenNonWebService_returnsNoReport() {
    NetworkService nonWebService = buildNonWebService(22); // SSH service
    TargetInfo targetInfo = buildTargetInfo(nonWebService);

    DetectionReportList detectionReports =
        detector.detect(targetInfo, ImmutableList.of(nonWebService));

    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
  }


  @Test
  public void detect_whenHttpClientThrowsIOException_returnsNoReportAndLogs() throws IOException {
    NetworkService mlflowService = buildWebService(5000);
    TargetInfo targetInfo = buildTargetInfo(mlflowService);

    when(mockHttpClient.send(any(HttpRequest.class), any(NetworkService.class)))
        .thenThrow(new IOException("Simulated network error"));

    DetectionReportList detectionReports =
        detector.detect(targetInfo, ImmutableList.of(mlflowService));

    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
    // Verification of logging would require a more complex setup (e.g., TestAppender for Logback/Flogger)
  }

  @Test
  public void detect_whenIsMlflowServiceFalse_returnsNoReport() {
    // Test the isMlflowService logic - current logic is port-based
    NetworkService nonMlflowPortWebService = buildWebService(8001); // Not 5000, 80, or 443
    TargetInfo targetInfo = buildTargetInfo(nonMlflowPortWebService);

    DetectionReportList detectionReports =
        detector.detect(targetInfo, ImmutableList.of(nonMlflowPortWebService));

    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
  }

  @Test
  public void detect_whenIsMlflowServiceTrueForPort80_attemptsScan() throws IOException {
    NetworkService mlflowServicePort80 = buildWebService(80);
    TargetInfo targetInfo = buildTargetInfo(mlflowServicePort80);

    HttpResponse mockHttpResponse = mock(HttpResponse.class);
    when(mockHttpResponse.status()).thenReturn(com.google.tsunami.common.net.http.HttpStatus.OK);
     when(mockHttpClient.send(
            AdditionalMatchers.and(
                HttpRequest.get("http://localhost:80/api/2.0/mlflow/experiments/list").build(),
                HttpRequest.get("http://localhost:80/api/2.0/mlflow/experiments/list")
                    .withCredentials(DEFAULT_USERNAME, DEFAULT_PASSWORD)
                    .build()),
            any(NetworkService.class)))
        .thenReturn(mockHttpResponse);

    DetectionReportList detectionReports =
        detector.detect(targetInfo, ImmutableList.of(mlflowServicePort80));

    assertThat(detectionReports.getDetectionReportsList()).hasSize(1); // Expecting a report
  }

   @Test
  public void detect_whenIsMlflowServiceTrueForPort443_attemptsScan() throws IOException {
    NetworkService mlflowServicePort443 = buildWebService(443);
    // For HTTPS, NetworkServiceUtils.buildWebApplicationUrl should handle it
    // We need to ensure our mock HttpClient is configured for this if it were a real HTTPS call
    // but for mocking, the URL string is the main thing.
    TargetInfo targetInfo = buildTargetInfo(mlflowServicePort443);


    HttpResponse mockHttpResponse = mock(HttpResponse.class);
    when(mockHttpResponse.status()).thenReturn(com.google.tsunami.common.net.http.HttpStatus.OK);
     when(mockHttpClient.send(
            AdditionalMatchers.and(
                HttpRequest.get("https://localhost:443/api/2.0/mlflow/experiments/list").build(),
                HttpRequest.get("https://localhost:443/api/2.0/mlflow/experiments/list")
                    .withCredentials(DEFAULT_USERNAME, DEFAULT_PASSWORD)
                    .build()),
            any(NetworkService.class)))
        .thenReturn(mockHttpResponse);


    DetectionReportList detectionReports =
        detector.detect(targetInfo, ImmutableList.of(mlflowServicePort443));

    assertThat(detectionReports.getDetectionReportsList()).hasSize(1);
  }
}
