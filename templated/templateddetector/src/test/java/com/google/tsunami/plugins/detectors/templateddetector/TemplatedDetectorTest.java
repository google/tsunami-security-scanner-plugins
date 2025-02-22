package com.google.tsunami.plugins.detectors.templateddetector;

import static com.google.common.truth.Truth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostnameAndPort;
import static org.junit.Assert.assertThrows;

import com.google.common.collect.ImmutableList;
import com.google.inject.Guice;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.common.time.testing.FakeUtcClockModule;
import com.google.tsunami.plugin.payload.testing.FakePayloadGeneratorModule;
import com.google.tsunami.proto.AdditionalDetail;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.PluginInfo;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.TransportProtocol;
import com.google.tsunami.proto.Vulnerability;
import com.google.tsunami.proto.VulnerabilityId;
import com.google.tsunami.templatedplugin.proto.HttpAction;
import com.google.tsunami.templatedplugin.proto.PluginAction;
import com.google.tsunami.templatedplugin.proto.PluginWorkflow;
import com.google.tsunami.templatedplugin.proto.TemplatedPlugin;
import java.io.IOException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Arrays;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class TemplatedDetectorTest {

  private static final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2020-01-01T00:00:00.00Z"));
  private static final SecureRandom testSecureRandom =
      new SecureRandom() {
        @Override
        public void nextBytes(byte[] bytes) {
          Arrays.fill(bytes, (byte) 0xFF);
        }
      };
  private static final PluginAction ACTION_RETURNS_TRUE =
      PluginAction.newBuilder()
          .setName("action_returns_true")
          .setHttpRequest(
              HttpAction.newBuilder()
                  .setMethod(HttpAction.HttpMethod.GET)
                  .addUri("/OK")
                  .setResponse(HttpAction.HttpResponse.newBuilder().setHttpStatus(200)))
          .build();
  private static final PluginAction ACTION_RETURNS_FALSE =
      PluginAction.newBuilder()
          .setName("action_returns_false")
          .setHttpRequest(
              HttpAction.newBuilder()
                  .setMethod(HttpAction.HttpMethod.GET)
                  .addUri("/NOTFOUND")
                  .setResponse(HttpAction.HttpResponse.newBuilder().setHttpStatus(200)))
          .build();
  private static final PluginAction ACTION_CLEANUP =
      ACTION_RETURNS_TRUE.toBuilder()
          .setName("action_cleanup")
          .setHttpRequest(
              HttpAction.newBuilder().setMethod(HttpAction.HttpMethod.GET).addUri("/CLEANUP"))
          .build();
  private static final TemplatedPlugin BASE_PROTO =
      TemplatedPlugin.newBuilder()
          .setInfo(PluginInfo.newBuilder().setName("ExampleTemplated"))
          .addActions(ACTION_CLEANUP)
          .addActions(ACTION_RETURNS_TRUE)
          .addActions(
              ACTION_RETURNS_TRUE.toBuilder()
                  .setName("action_returns_true_with_cleanup")
                  .addCleanupActions("action_cleanup"))
          .addActions(ACTION_RETURNS_FALSE)
          .addActions(
              ACTION_RETURNS_FALSE.toBuilder()
                  .setName("action_returns_false_with_cleanup")
                  .addCleanupActions("action_cleanup"))
          .build();

  private MockWebServer mockWebServer;
  private ImmutableList<NetworkService> httpServices;
  private TargetInfo targetInfo;

  @Before
  public void setupMockHttp() {
    this.mockWebServer = new MockWebServer();
    Dispatcher dispatcher =
        new Dispatcher() {
          @Override
          public MockResponse dispatch(RecordedRequest request) throws InterruptedException {
            if (request.getPath().equals("/OK")) {
              return new MockResponse().setResponseCode(200);
            }

            return new MockResponse().setResponseCode(404);
          }
        };
    this.mockWebServer.setDispatcher(dispatcher);

    var endpoint = forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort());
    this.httpServices =
        ImmutableList.of(
            NetworkService.newBuilder()
                .setNetworkEndpoint(endpoint)
                .setTransportProtocol(TransportProtocol.TCP)
                .setServiceName("http")
                .build());
    this.targetInfo = TargetInfo.newBuilder().addNetworkEndpoints(endpoint).build();
  }

  @After
  public void tearMockHttp() throws IOException {
    this.mockWebServer.shutdown();
  }

  @Test
  public void detect_workflowSucceeds_returnsFindings() throws InterruptedException {
    var proto =
        BASE_PROTO.toBuilder()
            .addWorkflows(PluginWorkflow.newBuilder().addActions("action_returns_true"))
            .build();
    var detector = setupDetector(proto);

    assertThat(detector.detect(this.targetInfo, this.httpServices).getDetectionReportsCount())
        .isEqualTo(1);
    assertThat(this.mockWebServer.getRequestCount()).isEqualTo(1);
    assertThat(this.mockWebServer.takeRequest().getPath()).isEqualTo("/OK");
  }

  @Test
  public void detect_workflowFails_returnsNoFindings() throws InterruptedException {
    var proto =
        BASE_PROTO.toBuilder()
            .addWorkflows(PluginWorkflow.newBuilder().addActions("action_returns_false"))
            .build();
    var detector = setupDetector(proto);

    assertThat(detector.detect(this.targetInfo, this.httpServices).getDetectionReportsCount())
        .isEqualTo(0);
    assertThat(this.mockWebServer.getRequestCount()).isEqualTo(1);
    assertThat(this.mockWebServer.takeRequest().getPath()).isEqualTo("/NOTFOUND");
  }

  @Test
  public void detect_noEligibleWorkflow_returnsNoFindings() throws InterruptedException {
    var proto =
        BASE_PROTO.toBuilder()
            .addWorkflows(
                PluginWorkflow.newBuilder()
                    .addActions("action_returns_true")
                    .setCondition(PluginWorkflow.Condition.REQUIRES_CALLBACK_SERVER))
            .build();
    var detector = setupDetector(proto);

    assertThat(detector.detect(this.targetInfo, this.httpServices).getDetectionReportsCount())
        .isEqualTo(0);
    assertThat(this.mockWebServer.getRequestCount()).isEqualTo(0);
  }

  @Test
  public void detect_eligibleWorkflow_returnsFindings() throws InterruptedException {
    var proto =
        BASE_PROTO.toBuilder()
            .addWorkflows(
                PluginWorkflow.newBuilder()
                    .addActions("action_returns_false")
                    .setCondition(PluginWorkflow.Condition.REQUIRES_CALLBACK_SERVER))
            .addWorkflows(PluginWorkflow.newBuilder().addActions("action_returns_true"))
            .build();
    var detector = setupDetector(proto);

    assertThat(detector.detect(this.targetInfo, this.httpServices).getDetectionReportsCount())
        .isEqualTo(1);
    assertThat(this.mockWebServer.getRequestCount()).isEqualTo(1);
    assertThat(this.mockWebServer.takeRequest().getPath()).isEqualTo("/OK");
  }

  @Test
  public void detect_severalEligibleWorkflows_picksFirstAndReturnsFindings()
      throws InterruptedException {
    var proto =
        BASE_PROTO.toBuilder()
            .addWorkflows(PluginWorkflow.newBuilder().addActions("action_returns_true"))
            .addWorkflows(PluginWorkflow.newBuilder().addActions("action_returns_false"))
            .build();
    var detector = setupDetector(proto);

    assertThat(detector.detect(this.targetInfo, this.httpServices).getDetectionReportsCount())
        .isEqualTo(1);
    assertThat(this.mockWebServer.getRequestCount()).isEqualTo(1);
    assertThat(this.mockWebServer.takeRequest().getPath()).isEqualTo("/OK");
  }

  @Test
  public void detect_unknownActionType_throwsException() {
    var proto =
        TemplatedPlugin.newBuilder()
            .setInfo(PluginInfo.newBuilder().setName("ExampleTemplated"))
            .addActions(PluginAction.newBuilder().setName("invalid_action_type"))
            .addWorkflows(PluginWorkflow.newBuilder().addActions("invalid_action_type"))
            .build();
    var detector = setupDetector(proto);

    assertThrows(
        IllegalArgumentException.class, () -> detector.detect(this.targetInfo, this.httpServices));
    assertThat(this.mockWebServer.getRequestCount()).isEqualTo(0);
  }

  @Test
  public void detect_unknownActionNameInWorkflow_throwsException() {
    var proto =
        BASE_PROTO.toBuilder()
            .addWorkflows(PluginWorkflow.newBuilder().addActions("undefined_action"))
            .build();
    var detector = setupDetector(proto);

    assertThrows(
        IllegalArgumentException.class, () -> detector.detect(this.targetInfo, this.httpServices));
    assertThat(this.mockWebServer.getRequestCount()).isEqualTo(0);
  }

  @Test
  public void detect_unknownCleanupNameInAction_throwsException() {
    var proto =
        BASE_PROTO.toBuilder()
            .addActions(
                PluginAction.newBuilder()
                    .setName("action_with_undefined_cleanup")
                    .addCleanupActions("undefined_cleanup"))
            .addWorkflows(PluginWorkflow.newBuilder().addActions("action_with_undefined_cleanup"))
            .build();
    var detector = setupDetector(proto);

    assertThrows(
        IllegalArgumentException.class, () -> detector.detect(this.targetInfo, this.httpServices));
  }

  @Test
  public void detect_variableFromWorkflow_propagatedAndReturnsFindings()
      throws InterruptedException {
    var proto =
        BASE_PROTO.toBuilder()
            .addActions(
                PluginAction.newBuilder()
                    .setName("action_using_workflow_variable")
                    .setHttpRequest(
                        HttpAction.newBuilder()
                            .setMethod(HttpAction.HttpMethod.GET)
                            .addUri("/{{ workflow_variable }}")
                            .setResponse(HttpAction.HttpResponse.newBuilder().setHttpStatus(200))))
            .addWorkflows(
                PluginWorkflow.newBuilder()
                    .addActions("action_using_workflow_variable")
                    .addVariables(
                        PluginWorkflow.Variable.newBuilder()
                            .setName("workflow_variable")
                            .setValue("OK")
                            .build()))
            .build();
    var detector = setupDetector(proto);

    assertThat(detector.detect(this.targetInfo, this.httpServices).getDetectionReportsCount())
        .isEqualTo(1);
    assertThat(this.mockWebServer.getRequestCount()).isEqualTo(1);
    assertThat(this.mockWebServer.takeRequest().getPath()).isEqualTo("/OK");
  }

  @Test
  public void detect_customFinding_returnsCustomFinding() throws InterruptedException {
    var finding =
        Vulnerability.newBuilder()
            .setMainId(VulnerabilityId.newBuilder().setPublisher("TSUNAMI").setValue("TESTPLUGIN"))
            .setSeverity(Severity.HIGH)
            .setTitle("Some vulnerability")
            .setDescription("Some vulnerability description")
            .setRecommendation("Some vulnerability recommendation")
            .addRelatedId(
                VulnerabilityId.newBuilder().setPublisher("CVE").setValue("CVE-2024-12345"))
            .addAdditionalDetails(
                AdditionalDetail.newBuilder().setDescription("Some additional detail"))
            .build();
    var expect =
        DetectionReport.newBuilder()
            .setTargetInfo(this.targetInfo)
            .setNetworkService(this.httpServices.get(0))
            .setDetectionTimestamp(Timestamps.fromMillis(fakeUtcClock.instant().toEpochMilli()))
            .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
            .setVulnerability(finding)
            .build();
    var proto =
        BASE_PROTO.toBuilder()
            .addWorkflows(PluginWorkflow.newBuilder().addActions("action_returns_true"))
            .setFinding(finding)
            .build();
    var detector = setupDetector(proto);

    assertThat(detector.detect(this.targetInfo, this.httpServices).getDetectionReportsList())
        .containsExactly(expect);
  }

  @Test
  public void detect_cleanupOnFailingAction_cleanupDoesNotRun() throws InterruptedException {
    var proto =
        BASE_PROTO.toBuilder()
            .addWorkflows(
                PluginWorkflow.newBuilder().addActions("action_returns_false_with_cleanup"))
            .build();
    var detector = setupDetector(proto);

    assertThat(detector.detect(this.targetInfo, this.httpServices).getDetectionReportsCount())
        .isEqualTo(0);
    assertThat(this.mockWebServer.getRequestCount()).isEqualTo(1);
    assertThat(this.mockWebServer.takeRequest().getPath()).isEqualTo("/NOTFOUND");
  }

  @Test
  public void detect_cleanupOnSuccessfulAction_cleanupRunsAfterLastSuccessAction()
      throws InterruptedException {
    var proto =
        BASE_PROTO.toBuilder()
            .addWorkflows(
                PluginWorkflow.newBuilder()
                    .addActions("action_returns_true_with_cleanup")
                    .addActions("action_returns_true"))
            .build();
    var detector = setupDetector(proto);

    assertThat(detector.detect(this.targetInfo, this.httpServices).getDetectionReportsCount())
        .isEqualTo(1);
    assertThat(this.mockWebServer.getRequestCount()).isEqualTo(3);
    assertThat(this.mockWebServer.takeRequest().getPath()).isEqualTo("/OK");
    assertThat(this.mockWebServer.takeRequest().getPath()).isEqualTo("/OK");
    assertThat(this.mockWebServer.takeRequest().getPath()).isEqualTo("/CLEANUP");
  }

  @Test
  public void detect_cleanupOnSuccessfulAction_cleanupRunsAfterLastFailAction()
      throws InterruptedException {
    var proto =
        BASE_PROTO.toBuilder()
            .addWorkflows(
                PluginWorkflow.newBuilder()
                    .addActions("action_returns_true_with_cleanup")
                    .addActions("action_returns_false")
                    .addActions("action_returns_true"))
            .build();
    var detector = setupDetector(proto);

    assertThat(detector.detect(this.targetInfo, this.httpServices).getDetectionReportsCount())
        .isEqualTo(0);
    assertThat(this.mockWebServer.getRequestCount()).isEqualTo(3);
    assertThat(this.mockWebServer.takeRequest().getPath()).isEqualTo("/OK");
    assertThat(this.mockWebServer.takeRequest().getPath()).isEqualTo("/NOTFOUND");
    assertThat(this.mockWebServer.takeRequest().getPath()).isEqualTo("/CLEANUP");
  }

  private TemplatedDetector setupDetector(TemplatedPlugin proto) {
    TemplatedDetector detector = new TemplatedDetector(proto);
    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new HttpClientModule.Builder().build(),
            FakePayloadGeneratorModule.builder().setSecureRng(testSecureRandom).build())
        .injectMembers(detector);
    return detector;
  }
}
