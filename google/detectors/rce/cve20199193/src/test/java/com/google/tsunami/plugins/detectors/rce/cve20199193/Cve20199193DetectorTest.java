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
package com.google.tsunami.plugins.detectors.rce.cve20199193;

import static com.google.common.truth.extensions.proto.ProtoTruth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostnameAndPort;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forIpAndPort;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.matches;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.google.common.collect.ImmutableList;
import com.google.inject.Guice;
import com.google.inject.testing.fieldbinder.Bind;
import com.google.inject.testing.fieldbinder.BoundFieldModule;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.common.time.testing.FakeUtcClockModule;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.TargetInfo;
import java.io.IOException;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Instant;
import javax.inject.Inject;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;

/** Unit tests for {@link Cve20199193Detector}. */
@RunWith(JUnit4.class)
public final class Cve20199193DetectorTest {

  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2020-01-01T00:00:00.00Z"));
  private static final String ID_OUTPUT =
      "uid=999(postgres) gid=999(postgres) groups=999(postgres),103(ssl-cert)";
  private static final String WRONG_LOGIN =
      "FATAL: password authentication failed for user \"postgres\"";
  private static final String CONNECTION_FAILED = "The connection attempt failed.";

  @Rule public MockitoRule rule = MockitoJUnit.rule();

  @Inject private Cve20199193Detector detector;

  @Bind @Mock private ConnectionProviderInterface mockConnectionProvider;
  @Mock private Connection mockConnection;
  @Mock private Statement mockStatement;
  @Mock private ResultSet mockResultSet;

  @Before
  public void setUp() throws IOException {
    Guice.createInjector(BoundFieldModule.of(this), new FakeUtcClockModule(fakeUtcClock))
        .injectMembers(this);
  }

  @Test
  public void detect_exploitable_returnsVuln() throws IOException, SQLException {
    when(mockConnectionProvider.getConnection(any(), any(), any())).thenReturn(mockConnection);
    when(mockConnection.createStatement()).thenReturn(mockStatement);
    when(mockStatement.executeUpdate(any())).thenReturn(0);
    when(mockStatement.executeQuery(any())).thenReturn(mockResultSet);
    when(mockResultSet.next()).thenReturn(true);
    when(mockResultSet.getString(1)).thenReturn(ID_OUTPUT);

    NetworkService targetNetworkService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(forHostnameAndPort("example.com", 5432))
            .build();
    TargetInfo targetInfo =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(targetNetworkService.getNetworkEndpoint())
            .build();

    var report = detector.detect(targetInfo, ImmutableList.of(targetNetworkService));

    InOrder inOrder = inOrder(mockStatement);
    inOrder.verify(mockStatement).executeUpdate(matches("CREATE TABLE .*"));
    inOrder.verify(mockStatement).executeUpdate(matches("COPY .* FROM PROGRAM '.*'"));
    inOrder.verify(mockStatement).executeQuery(matches("SELECT .*FROM .*"));
    inOrder.verify(mockStatement).executeUpdate(matches("DROP TABLE .*"));
    inOrder.verify(mockStatement).close();

    assertThat(report.getDetectionReportsList())
        .containsExactly(
            DetectionReport.newBuilder()
                .setTargetInfo(targetInfo)
                .setNetworkService(targetNetworkService)
                .setDetectionTimestamp(
                    Timestamps.fromMillis(Instant.now(fakeUtcClock).toEpochMilli()))
                .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
                .setVulnerability(Cve20199193Detector.VULNERABILITY)
                .build());
  }

  @Test
  public void detect_wrongResponse_returnsFalse() throws IOException, SQLException {
    when(mockConnectionProvider.getConnection(any(), any(), any())).thenReturn(mockConnection);
    when(mockConnection.createStatement()).thenReturn(mockStatement);
    when(mockStatement.executeUpdate(any())).thenReturn(0);
    when(mockStatement.executeQuery(any())).thenReturn(mockResultSet);
    when(mockResultSet.next()).thenReturn(true);
    when(mockResultSet.getString(1)).thenReturn("not id output");

    NetworkService targetNetworkService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(forHostnameAndPort("example.com", 5432))
            .build();
    TargetInfo targetInfo =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(targetNetworkService.getNetworkEndpoint())
            .build();

    var report = detector.detect(targetInfo, ImmutableList.of(targetNetworkService));

    assertThat(report.getDetectionReportsList()).isEmpty();
  }

  @Test
  public void detect_wrongLogin_noVuln() throws IOException, SQLException {
    when(mockConnectionProvider.getConnection(any(), any(), any()))
        .thenThrow(new SQLException(WRONG_LOGIN));

    NetworkService targetNetworkService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(forHostnameAndPort("example.com", 5432))
            .build();
    TargetInfo targetInfo =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(targetNetworkService.getNetworkEndpoint())
            .build();

    var report = detector.detect(targetInfo, ImmutableList.of(targetNetworkService));

    assertThat(report.getDetectionReportsList()).isEmpty();
  }

  @Test
  public void detect_wrongEndpoint_noVuln() throws IOException, SQLException {
    when(mockConnectionProvider.getConnection(any(), any(), any()))
        .thenThrow(new SQLException(CONNECTION_FAILED));

    NetworkService targetNetworkService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(forHostnameAndPort("example.com", 1234))
            .build();
    TargetInfo targetInfo =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(targetNetworkService.getNetworkEndpoint())
            .build();

    var report = detector.detect(targetInfo, ImmutableList.of(targetNetworkService));

    verify(mockConnectionProvider)
        .getConnection(eq("jdbc:postgresql://example.com:1234/postgres"), any(), any());
    assertThat(report.getDetectionReportsList()).isEmpty();
  }

  @Test
  public void detect_hostname_returnsVuln() throws IOException, SQLException {
    when(mockConnectionProvider.getConnection(any(), any(), any())).thenReturn(mockConnection);
    when(mockConnection.createStatement()).thenReturn(mockStatement);
    when(mockStatement.executeUpdate(any())).thenReturn(0);
    when(mockStatement.executeQuery(any())).thenReturn(mockResultSet);
    when(mockResultSet.next()).thenReturn(true);
    when(mockResultSet.getString(1)).thenReturn(ID_OUTPUT);

    NetworkService targetNetworkService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(forHostnameAndPort("example.com", 5432))
            .build();
    TargetInfo targetInfo =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(targetNetworkService.getNetworkEndpoint())
            .build();

    var report = detector.detect(targetInfo, ImmutableList.of(targetNetworkService));

    verify(mockConnectionProvider)
        .getConnection(eq("jdbc:postgresql://example.com:5432/postgres"), any(), any());

    assertThat(report.getDetectionReportsList())
        .containsExactly(
            DetectionReport.newBuilder()
                .setTargetInfo(targetInfo)
                .setNetworkService(targetNetworkService)
                .setDetectionTimestamp(
                    Timestamps.fromMillis(Instant.now(fakeUtcClock).toEpochMilli()))
                .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
                .setVulnerability(Cve20199193Detector.VULNERABILITY)
                .build());
  }

  @Test
  public void detect_ip_returnsVuln() throws IOException, SQLException {
    when(mockConnectionProvider.getConnection(any(), any(), any())).thenReturn(mockConnection);
    when(mockConnection.createStatement()).thenReturn(mockStatement);
    when(mockStatement.executeUpdate(any())).thenReturn(0);
    when(mockStatement.executeQuery(any())).thenReturn(mockResultSet);
    when(mockResultSet.next()).thenReturn(true);
    when(mockResultSet.getString(1)).thenReturn(ID_OUTPUT);

    NetworkService targetNetworkService =
        NetworkService.newBuilder().setNetworkEndpoint(forIpAndPort("192.168.1.2", 1234)).build();
    TargetInfo targetInfo =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(targetNetworkService.getNetworkEndpoint())
            .build();

    var report = detector.detect(targetInfo, ImmutableList.of(targetNetworkService));

    verify(mockConnectionProvider)
        .getConnection(eq("jdbc:postgresql://192.168.1.2:1234/postgres"), any(), any());

    assertThat(report.getDetectionReportsList())
        .containsExactly(
            DetectionReport.newBuilder()
                .setTargetInfo(targetInfo)
                .setNetworkService(targetNetworkService)
                .setDetectionTimestamp(
                    Timestamps.fromMillis(Instant.now(fakeUtcClock).toEpochMilli()))
                .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
                .setVulnerability(Cve20199193Detector.VULNERABILITY)
                .build());
  }

  @Test
  public void detect_noEndpoint_returnFalse() throws IOException, SQLException {
    NetworkService targetNetworkService = NetworkService.getDefaultInstance();
    TargetInfo targetInfo = TargetInfo.getDefaultInstance();

    var report = detector.detect(targetInfo, ImmutableList.of(targetNetworkService));

    verify(mockConnectionProvider, never()).getConnection(any(), any(), any());
    assertThat(report.getDetectionReportsList()).isEmpty();
  }
}
