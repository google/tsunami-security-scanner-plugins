/*
 * Copyright 2021 Google LLC
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
package com.google.tsunami.plugins.detectors.rce.redis;

import static com.google.common.truth.Truth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostnameAndPort;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forIp;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forIpAndPort;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forIpHostnameAndPort;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.intThat;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.google.inject.AbstractModule;
import com.google.inject.Guice;
import com.google.tsunami.common.net.socket.TsunamiSocketFactory;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.common.time.testing.FakeUtcClockModule;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkEndpoint;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.Port;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.TransportProtocol;
import com.google.tsunami.proto.Vulnerability;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicLong;
import javax.inject.Inject;
import javax.net.ssl.SSLSocket;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link RedisUnauthenticatedCommandExecutionDetector}. */
@RunWith(JUnit4.class)
public final class RedisUnauthenticatedCommandExecutionDetectorTest {
  private static final Duration EXPECTED_SESSION_TIMEOUT = Duration.ofSeconds(5);
  private static final int TEST_SOCKET_TIMEOUT_MS = 2000;
  private static final int SERVER_CLIENT_TIMEOUT_MS = 3000;
  private static final int SERVER_BACKLOG = 16;

  private static final ImmutableList<String> INFO_SERVER = ImmutableList.of("INFO", "server");
  private static final ImmutableList<String> CONFIG_GET_PROTECTED =
      ImmutableList.of("CONFIG", "GET", "enable-protected-configs");
  private static final ImmutableList<String> CONFIG_GET_MODULE =
      ImmutableList.of("CONFIG", "GET", "enable-module-command");
  private static final ImmutableList<String> CONFIG_SET_DBFILENAME =
      ImmutableList.of("CONFIG", "SET", "dbfilename", "a/b");
  private static final ImmutableList<String> CONFIG_SET_SYNTHETIC =
      ImmutableList.of("CONFIG", "SET", "__tsunami_ro_probe__", "");
  private static final ImmutableList<String> MODULE_LOADEX =
      ImmutableList.of("MODULE", "LOADEX", "", "CONFIG");
  private static final ImmutableList<String> MODULE_UNLOAD =
      ImmutableList.of("MODULE", "UNLOAD", "__tsunami_ro_probe__");

  private static final ImmutableSet<ImmutableList<String>> ALLOWED_PROBE_COMMANDS =
      ImmutableSet.of(
          INFO_SERVER,
          CONFIG_GET_PROTECTED,
          CONFIG_GET_MODULE,
          CONFIG_SET_DBFILENAME,
          CONFIG_SET_SYNTHETIC,
          MODULE_LOADEX,
          MODULE_UNLOAD);

  private static final Instant FIXED_INSTANT = Instant.parse("2026-01-01T00:00:00.00Z");

  private final FakeUtcClock fakeUtcClock = FakeUtcClock.create().setNow(FIXED_INSTANT);

  private final TsunamiSocketFactory socketFactoryMock = mock(TsunamiSocketFactory.class);

  @Inject private RedisUnauthenticatedCommandExecutionDetector detector;

  @Before
  public void setUp() {
    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new RedisUnauthenticatedCommandExecutionDetectorBootstrapModule(),
            new AbstractModule() {
              @Override
              protected void configure() {
                bind(TsunamiSocketFactory.class).toInstance(socketFactoryMock);
              }
            })
        .injectMembers(this);
  }

  @Test
  public void getAdvisories_returnsCriticalRceAndHighReadWriteAdvisories() {
    ImmutableList<Vulnerability> advisories = detector.getAdvisories();
    assertThat(advisories).hasSize(2);
    assertThat(advisories.get(0).getMainId().getValue())
        .isEqualTo("REDIS_UNAUTHENTICATED_COMMAND_EXECUTION");
    assertThat(advisories.get(0).getSeverity()).isEqualTo(Severity.CRITICAL);
    assertThat(advisories.get(1).getMainId().getValue())
        .isEqualTo("REDIS_UNAUTHENTICATED_READ_WRITE_ACCESS");
    assertThat(advisories.get(1).getSeverity()).isEqualTo(Severity.HIGH);
  }

  @Test
  public void detect_whenRedis7ProtectedConfigsUnlocked_returnsCriticalRce() throws Exception {
    try (FakeRespServer server =
        new FakeRespServer(
            ImmutableMap.of(
                INFO_SERVER, bulk("# Server\r\nredis_version:7.2.5\r\nos:Linux\r\n"),
                CONFIG_GET_PROTECTED, kvArray("enable-protected-configs", "yes"),
                CONFIG_SET_DBFILENAME, "-ERR dbfilename can't be a path, just a filename\r\n",
                CONFIG_GET_MODULE, kvArray("enable-module-command", "no")))) {
      NetworkService service = tcpService("redis", server.port());
      DetectionReport report = detectSingleFinding(server, service);

      assertThat(report.getDetectionStatus()).isEqualTo(DetectionStatus.VULNERABILITY_VERIFIED);
      assertThat(report.getNetworkService()).isEqualTo(service);
      assertThat(report.getDetectionTimestamp().getSeconds())
          .isEqualTo(FIXED_INSTANT.getEpochSecond());
      assertThat(report.getDetectionTimestamp().getNanos()).isEqualTo(0);
      assertThat(report.getVulnerability().getMainId().getValue())
          .isEqualTo("REDIS_UNAUTHENTICATED_COMMAND_EXECUTION");
      assertThat(report.getVulnerability().getSeverity()).isEqualTo(Severity.CRITICAL);
      assertThat(assessmentText(report)).contains("CONFIG SET dir/dbfilename permitted");
      assertThat(infoExcerptText(report)).contains("redis_version:7.2.5");
      assertNoMutatingCommands(server.commands());
    }
  }

  @Test
  public void detect_whenRedis7GatesSetToLocalAndPermitted_returnsCriticalRce() throws Exception {
    try (FakeRespServer server =
        new FakeRespServer(
            ImmutableMap.of(
                INFO_SERVER, bulk("# Server\r\nredis_version:7.2.5\r\n"),
                CONFIG_GET_PROTECTED, kvArray("enable-protected-configs", "local"),
                CONFIG_SET_DBFILENAME, "-ERR dbfilename can't be a path, just a filename\r\n",
                CONFIG_GET_MODULE, kvArray("enable-module-command", "local"),
                MODULE_LOADEX,
                    "-ERR Error loading the extension. Please check the server logs.\r\n"))) {
      DetectionReport report = detectSingleFinding(server, "redis");

      assertThat(report.getVulnerability().getSeverity()).isEqualTo(Severity.CRITICAL);
      assertThat(assessmentText(report)).contains("CONFIG SET dir/dbfilename permitted");
      assertThat(assessmentText(report)).contains("MODULE LOADEX permitted");
      assertNoMutatingCommands(server.commands());
    }
  }

  @Test
  public void detect_whenRedis7ModuleCommandUnlocked_returnsCriticalRce() throws Exception {
    try (FakeRespServer server =
        new FakeRespServer(
            ImmutableMap.of(
                INFO_SERVER, bulk("# Server\r\nredis_version:7.2.5\r\n"),
                CONFIG_GET_PROTECTED, kvArray("enable-protected-configs", "no"),
                CONFIG_GET_MODULE, kvArray("enable-module-command", "yes"),
                MODULE_LOADEX,
                    "-ERR Error loading the extension. Please check the server logs.\r\n"))) {
      DetectionReport report = detectSingleFinding(server, "redis");

      assertThat(report.getVulnerability().getSeverity()).isEqualTo(Severity.CRITICAL);
      assertThat(assessmentText(report)).contains("MODULE LOADEX permitted");
      assertNoMutatingCommands(server.commands());
    }
  }

  @Test
  public void detect_whenRedis6DefaultUnprotected_returnsCriticalRce() throws Exception {
    try (FakeRespServer server =
        new FakeRespServer(
            ImmutableMap.of(
                INFO_SERVER, bulk("# Server\r\nredis_version:6.2.14\r\n"),
                CONFIG_GET_PROTECTED, "*0\r\n",
                CONFIG_SET_DBFILENAME, "-ERR dbfilename can't be a path, just a filename\r\n",
                CONFIG_GET_MODULE, "*0\r\n",
                MODULE_LOADEX, "-ERR Unknown subcommand or wrong number\r\n",
                MODULE_UNLOAD, "-ERR Error unloading module: no such module with that name\r\n"))) {
      DetectionReport report = detectSingleFinding(server, "redis");

      assertThat(report.getVulnerability().getSeverity()).isEqualTo(Severity.CRITICAL);
      assertThat(assessmentText(report)).contains("CONFIG SET dir/dbfilename permitted");
      assertThat(assessmentText(report)).contains("MODULE LOAD/UNLOAD permitted");
      assertNoMutatingCommands(server.commands());
    }
  }

  @Test
  public void detect_whenValkey8HardenedDefaults_returnsHighReadWriteOnly() throws Exception {
    try (FakeRespServer server =
        new FakeRespServer(
            ImmutableMap.of(
                INFO_SERVER,
                    bulk(
                        """
                        # Server
                        server_name:valkey
                        valkey_version:8.0.1
                        redis_version:7.2.4
                        """),
                CONFIG_GET_PROTECTED, kvArray("enable-protected-configs", "no"),
                CONFIG_GET_MODULE, kvArray("enable-module-command", "no")))) {
      DetectionReport report = detectSingleFinding(server, "valkey");

      assertThat(report.getVulnerability().getMainId().getValue())
          .isEqualTo("REDIS_UNAUTHENTICATED_READ_WRITE_ACCESS");
      assertThat(report.getVulnerability().getSeverity()).isEqualTo(Severity.HIGH);
      assertThat(assessmentText(report))
          .contains("direct OS RCE gates (protected configs and module loading) are locked");
      assertThat(server.commands())
          .containsExactly(INFO_SERVER, CONFIG_GET_PROTECTED, CONFIG_GET_MODULE)
          .inOrder();
    }
  }

  @Test
  public void detect_whenRedis7LocalGatesRejectRemoteClient_returnsHighReadWrite()
      throws Exception {
    try (FakeRespServer server =
        new FakeRespServer(
            ImmutableMap.of(
                INFO_SERVER, bulk("# Server\r\nredis_version:7.2.5\r\n"),
                CONFIG_GET_PROTECTED, kvArray("enable-protected-configs", "local"),
                CONFIG_SET_DBFILENAME, "-ERR Can't set immutable config 'dbfilename'\r\n",
                CONFIG_GET_MODULE, kvArray("enable-module-command", "local"),
                MODULE_LOADEX, "-ERR MODULE command not allowed.\r\n",
                MODULE_UNLOAD, "-ERR Error unloading module: no such module with that name\r\n"))) {
      DetectionReport report = detectSingleFinding(server, "redis");

      assertThat(report.getVulnerability().getMainId().getValue())
          .isEqualTo("REDIS_UNAUTHENTICATED_READ_WRITE_ACCESS");
      assertThat(report.getVulnerability().getSeverity()).isEqualTo(Severity.HIGH);
      assertThat(assessmentText(report))
          .contains("direct OS RCE gates (protected configs and module loading) are locked");
      assertThat(server.commands())
          .containsExactly(
              INFO_SERVER,
              CONFIG_GET_PROTECTED,
              CONFIG_SET_DBFILENAME,
              CONFIG_GET_MODULE,
              MODULE_LOADEX)
          .inOrder();
    }
  }

  @Test
  public void detect_whenManagedRedis6DisablesConfigAndModules_returnsHighReadWrite()
      throws Exception {
    try (FakeRespServer server =
        new FakeRespServer(
            ImmutableMap.of(
                INFO_SERVER, bulk("# Server\r\nredis_version:6.2.16\r\n"),
                CONFIG_GET_PROTECTED, "-ERR unknown command 'CONFIG'\r\n",
                CONFIG_SET_DBFILENAME, "-ERR Unsupported CONFIG parameter: dbfilename\r\n",
                CONFIG_GET_MODULE, "-ERR unknown command 'CONFIG'\r\n",
                MODULE_LOADEX, "-ERR unknown command 'MODULE'\r\n"))) {
      DetectionReport report = detectSingleFinding(server, "redis");

      assertThat(report.getVulnerability().getMainId().getValue())
          .isEqualTo("REDIS_UNAUTHENTICATED_READ_WRITE_ACCESS");
      assertThat(report.getVulnerability().getSeverity()).isEqualTo(Severity.HIGH);
      assertThat(assessmentText(report))
          .contains("direct OS RCE gates (protected configs and module loading) are locked");
      assertThat(server.commands())
          .containsExactly(
              INFO_SERVER,
              CONFIG_GET_PROTECTED,
              CONFIG_SET_DBFILENAME,
              CONFIG_GET_MODULE,
              MODULE_LOADEX)
          .inOrder();
    }
  }

  @Test
  public void detect_whenRedis32BoundaryVersion_usesDbfilenameProbe() throws Exception {
    try (FakeRespServer server =
        new FakeRespServer(
            ImmutableMap.of(
                INFO_SERVER, bulk("# Server\r\nredis_version:3.2.0\r\n"),
                CONFIG_GET_PROTECTED, "*0\r\n",
                CONFIG_SET_DBFILENAME, "-ERR dbfilename can't be a path, just a filename\r\n",
                CONFIG_GET_MODULE, "*0\r\n",
                MODULE_LOADEX, "-ERR unknown command 'MODULE'\r\n"))) {
      DetectionReport report = detectSingleFinding(server, "redis");

      assertThat(report.getVulnerability().getSeverity()).isEqualTo(Severity.CRITICAL);
      assertThat(server.commands())
          .containsExactly(
              INFO_SERVER,
              CONFIG_GET_PROTECTED,
              CONFIG_SET_DBFILENAME,
              CONFIG_GET_MODULE,
              MODULE_LOADEX)
          .inOrder();
    }
  }

  @Test
  public void detect_whenLegacyRedisPre32BoundaryVersion_usesSyntheticConfigSetProbe()
      throws Exception {
    try (FakeRespServer server =
        new FakeRespServer(
            ImmutableMap.of(
                INFO_SERVER, bulk("# Server\r\nredis_version:3.1.9\r\n"),
                CONFIG_GET_PROTECTED, "*0\r\n",
                CONFIG_SET_SYNTHETIC, "-ERR Unsupported CONFIG parameter: __tsunami_ro_probe__\r\n",
                CONFIG_GET_MODULE, "*0\r\n",
                MODULE_LOADEX, "-ERR unknown command 'MODULE'\r\n"))) {
      DetectionReport report = detectSingleFinding(server, "redis");

      assertThat(report.getVulnerability().getSeverity()).isEqualTo(Severity.CRITICAL);
      assertThat(server.commands())
          .containsExactly(
              INFO_SERVER,
              CONFIG_GET_PROTECTED,
              CONFIG_SET_SYNTHETIC,
              CONFIG_GET_MODULE,
              MODULE_LOADEX)
          .inOrder();
    }
  }

  @Test
  public void detect_whenLegacyRedis28WithHighMinor_usesSyntheticConfigSetProbe() throws Exception {
    try (FakeRespServer server =
        new FakeRespServer(
            ImmutableMap.of(
                INFO_SERVER, bulk("# Server\r\nredis_version:2.8.24\r\n"),
                CONFIG_GET_PROTECTED, "*0\r\n",
                CONFIG_SET_SYNTHETIC, "-ERR Unsupported CONFIG parameter: __tsunami_ro_probe__\r\n",
                CONFIG_GET_MODULE, "*0\r\n",
                MODULE_LOADEX, "-ERR unknown command 'MODULE'\r\n"))) {
      DetectionReport report = detectSingleFinding(server, "redis");

      assertThat(report.getVulnerability().getSeverity()).isEqualTo(Severity.CRITICAL);
      assertThat(server.commands())
          .containsExactly(
              INFO_SERVER,
              CONFIG_GET_PROTECTED,
              CONFIG_SET_SYNTHETIC,
              CONFIG_GET_MODULE,
              MODULE_LOADEX)
          .inOrder();
    }
  }

  @Test
  public void detect_whenRedis70ZeroMinor_usesDbfilenameProbe() throws Exception {
    try (FakeRespServer server =
        new FakeRespServer(
            ImmutableMap.of(
                INFO_SERVER, bulk("# Server\r\nredis_version:7.0.15\r\n"),
                CONFIG_GET_PROTECTED, kvArray("enable-protected-configs", "local"),
                CONFIG_SET_DBFILENAME, "-ERR Can't set immutable config 'dbfilename'\r\n",
                CONFIG_GET_MODULE, kvArray("enable-module-command", "no")))) {
      DetectionReport report = detectSingleFinding(server, "redis");

      assertThat(report.getVulnerability().getSeverity()).isEqualTo(Severity.HIGH);
      assertThat(server.commands())
          .containsExactly(
              INFO_SERVER, CONFIG_GET_PROTECTED, CONFIG_SET_DBFILENAME, CONFIG_GET_MODULE)
          .inOrder();
    }
  }

  @Test
  public void detect_whenLegacyRedisPre32RejectsConfigSetWithUnknownOption_returnsHighReadWrite()
      throws Exception {
    try (FakeRespServer server =
        new FakeRespServer(
            ImmutableMap.of(
                INFO_SERVER, bulk("# Server\r\nredis_version:3.1.9\r\n"),
                CONFIG_GET_PROTECTED, "*0\r\n",
                CONFIG_SET_SYNTHETIC,
                    "-ERR Unknown option or number of arguments for CONFIG SET\r\n",
                CONFIG_GET_MODULE, "*0\r\n",
                MODULE_LOADEX, "-ERR unknown command 'MODULE'\r\n"))) {
      DetectionReport report = detectSingleFinding(server, "redis");

      assertThat(report.getVulnerability().getMainId().getValue())
          .isEqualTo("REDIS_UNAUTHENTICATED_READ_WRITE_ACCESS");
      assertThat(report.getVulnerability().getSeverity()).isEqualTo(Severity.HIGH);
      assertThat(server.commands())
          .containsExactly(
              INFO_SERVER,
              CONFIG_GET_PROTECTED,
              CONFIG_SET_SYNTHETIC,
              CONFIG_GET_MODULE,
              MODULE_LOADEX)
          .inOrder();
    }
  }

  @Test
  public void detect_whenRedis6ModuleUnloadReturnsDisallowedError_returnsHighReadWrite()
      throws Exception {
    try (FakeRespServer server =
        new FakeRespServer(
            ImmutableMap.of(
                INFO_SERVER, bulk("# Server\r\nredis_version:6.2.14\r\n"),
                CONFIG_GET_PROTECTED, "-ERR unknown command 'CONFIG'\r\n",
                CONFIG_SET_DBFILENAME, "-ERR unknown command 'CONFIG'\r\n",
                CONFIG_GET_MODULE, "-ERR unknown command 'CONFIG'\r\n",
                MODULE_LOADEX, "-ERR Unknown subcommand or wrong number\r\n",
                MODULE_UNLOAD, "-ERR MODULE command not allowed.\r\n"))) {
      DetectionReport report = detectSingleFinding(server, "redis");

      assertThat(report.getVulnerability().getMainId().getValue())
          .isEqualTo("REDIS_UNAUTHENTICATED_READ_WRITE_ACCESS");
      assertThat(report.getVulnerability().getSeverity()).isEqualTo(Severity.HIGH);
      assertThat(server.commands())
          .containsExactly(
              INFO_SERVER,
              CONFIG_GET_PROTECTED,
              CONFIG_SET_DBFILENAME,
              CONFIG_GET_MODULE,
              MODULE_LOADEX,
              MODULE_UNLOAD)
          .inOrder();
    }
  }

  @Test
  public void detect_whenLoadexReturnsWrongNumberOfArguments_fallsBackToModuleUnload()
      throws Exception {
    assertLoadexFallbackToModuleUnload("-ERR wrong number of arguments for 'module' command\r\n");
  }

  @Test
  public void detect_whenLoadexReturnsSyntaxError_fallsBackToModuleUnload() throws Exception {
    assertLoadexFallbackToModuleUnload("-ERR syntax error\r\n");
  }

  @Test
  public void detect_whenConfigOrModuleProbesReturnNonErrorMatchingText_returnsHighReadWrite()
      throws Exception {
    try (FakeRespServer server =
        new FakeRespServer(
            ImmutableMap.of(
                INFO_SERVER,
                bulk("# Server\r\nredis_version:7.2.5\r\n"),
                CONFIG_GET_PROTECTED,
                kvArray("enable-protected-configs", "yes"),
                CONFIG_SET_DBFILENAME,
                "+just a filename\r\n",
                CONFIG_GET_MODULE,
                kvArray("enable-module-command", "yes"),
                MODULE_LOADEX,
                bulk("Error loading the extension.")))) {
      DetectionReport report = detectSingleFinding(server, "redis");

      assertThat(report.getVulnerability().getMainId().getValue())
          .isEqualTo("REDIS_UNAUTHENTICATED_READ_WRITE_ACCESS");
      assertThat(report.getVulnerability().getSeverity()).isEqualTo(Severity.HIGH);
      assertThat(server.commands())
          .containsExactly(
              INFO_SERVER,
              CONFIG_GET_PROTECTED,
              CONFIG_SET_DBFILENAME,
              CONFIG_GET_MODULE,
              MODULE_LOADEX)
          .inOrder();
    }
  }

  @Test
  public void detect_whenUnparseableRedisVersion_skipsConfigProbePhase() throws Exception {
    try (FakeRespServer server =
        new FakeRespServer(
            ImmutableMap.of(
                INFO_SERVER, bulk("# Server\r\nredis_version:7-custom\r\n"),
                CONFIG_GET_MODULE, kvArray("enable-module-command", "no")))) {
      DetectionReport report = detectSingleFinding(server, "redis");

      assertThat(report.getVulnerability().getMainId().getValue())
          .isEqualTo("REDIS_UNAUTHENTICATED_READ_WRITE_ACCESS");
      assertThat(report.getVulnerability().getSeverity()).isEqualTo(Severity.HIGH);
      assertThat(assessmentText(report))
          .contains("runtime CONFIG SET probe skipped for unparsed Redis version");
      assertThat(server.commands()).containsExactly(INFO_SERVER, CONFIG_GET_MODULE).inOrder();
    }
  }

  @Test
  public void detect_whenDottedNonNumericMinorRedisVersion_skipsConfigProbePhase()
      throws Exception {
    try (FakeRespServer server =
        new FakeRespServer(
            ImmutableMap.of(
                INFO_SERVER, bulk("# Server\r\nredis_version:7.x\r\n"),
                CONFIG_GET_MODULE, kvArray("enable-module-command", "no")))) {
      DetectionReport report = detectSingleFinding(server, "redis");

      assertThat(report.getVulnerability().getSeverity()).isEqualTo(Severity.HIGH);
      assertThat(assessmentText(report))
          .contains("runtime CONFIG SET probe skipped for unparsed Redis version");
      assertThat(server.commands()).containsExactly(INFO_SERVER, CONFIG_GET_MODULE).inOrder();
    }
  }

  @Test
  public void detect_whenAclBlocksLoadexWithNopermEvenIfUnloadAllowed_returnsHighReadWrite()
      throws Exception {
    try (FakeRespServer server =
        new FakeRespServer(
            ImmutableMap.of(
                INFO_SERVER, bulk("# Server\r\nredis_version:7.4.1\r\n"),
                CONFIG_GET_PROTECTED, "-NOPERM no permissions to run 'config|get'\r\n",
                CONFIG_SET_DBFILENAME, "-NOPERM no permissions to run 'config|set'\r\n",
                CONFIG_GET_MODULE, "-NOPERM no permissions to run 'config|get'\r\n",
                MODULE_LOADEX, "-NOPERM no permissions to run 'module|loadex'\r\n",
                MODULE_UNLOAD, "-ERR Error unloading module: no such module with that name\r\n"))) {
      DetectionReport report = detectSingleFinding(server, "redis");

      assertThat(report.getVulnerability().getMainId().getValue())
          .isEqualTo("REDIS_UNAUTHENTICATED_READ_WRITE_ACCESS");
      assertThat(report.getVulnerability().getSeverity()).isEqualTo(Severity.HIGH);
      assertThat(assessmentText(report))
          .contains("direct OS RCE gates (protected configs and module loading) are locked");
      assertThat(server.commands())
          .containsExactly(
              INFO_SERVER,
              CONFIG_GET_PROTECTED,
              CONFIG_SET_DBFILENAME,
              CONFIG_GET_MODULE,
              MODULE_LOADEX)
          .inOrder();
    }
  }

  @Test
  public void detect_whenDragonflyCompatibleEngine_skipsConfigProbePhaseAndChecksModuleOnly()
      throws Exception {
    try (FakeRespServer server =
        new FakeRespServer(
            ImmutableMap.of(
                INFO_SERVER,
                    bulk(
                        """
                        # Server
                        redis_version:7.0.0
                        valkey_version:8.0.0
                        dragonfly_version:df-v1.24.0
                        """),
                CONFIG_GET_MODULE, "*0\r\n",
                MODULE_LOADEX, "-ERR unknown command 'MODULE'\r\n"))) {
      DetectionReport report = detectSingleFinding(server, "redis");

      assertThat(report.getVulnerability().getMainId().getValue())
          .isEqualTo("REDIS_UNAUTHENTICATED_READ_WRITE_ACCESS");
      assertThat(assessmentText(report))
          .contains(
              "runtime CONFIG SET probe skipped for compatibility engine; module loading gate is"
                  + " locked");
      assertThat(server.commands())
          .containsExactly(INFO_SERVER, CONFIG_GET_MODULE, MODULE_LOADEX)
          .inOrder();
      assertNoMutatingCommands(server.commands());
    }
  }

  @Test
  public void detect_whenDragonflyDevVersionWithoutDigits_skipsConfigProbePhase() throws Exception {
    try (FakeRespServer server =
        new FakeRespServer(
            ImmutableMap.of(
                INFO_SERVER, bulk("# Server\r\nredis_version:7.4.0\r\ndragonfly_version:dev\r\n"),
                CONFIG_GET_MODULE, "*0\r\n",
                MODULE_LOADEX, "-ERR unknown command 'MODULE'\r\n"))) {
      DetectionReport report = detectSingleFinding(server, "redis");

      assertThat(report.getVulnerability().getMainId().getValue())
          .isEqualTo("REDIS_UNAUTHENTICATED_READ_WRITE_ACCESS");
      assertThat(assessmentText(report)).contains("Engine: dragonfly dev");
      assertThat(server.commands())
          .containsExactly(INFO_SERVER, CONFIG_GET_MODULE, MODULE_LOADEX)
          .inOrder();
    }
  }

  @Test
  public void detect_whenEmptyCompatVersionAlongsideRedisVersion_skipsConfigProbePhase()
      throws Exception {
    try (FakeRespServer server =
        new FakeRespServer(
            ImmutableMap.of(
                INFO_SERVER, bulk("# Server\r\nredis_version:7.4.0\r\ndragonfly_version:\r\n"),
                CONFIG_GET_MODULE, "*0\r\n",
                MODULE_LOADEX, "-ERR unknown command 'MODULE'\r\n"))) {
      DetectionReport report = detectSingleFinding(server, "redis");

      assertThat(report.getVulnerability().getSeverity()).isEqualTo(Severity.HIGH);
      assertThat(assessmentText(report)).contains("Engine: dragonfly unknown");
      assertThat(assessmentText(report))
          .contains("runtime CONFIG SET probe skipped for compatibility engine");
      assertThat(server.commands())
          .containsExactly(INFO_SERVER, CONFIG_GET_MODULE, MODULE_LOADEX)
          .inOrder();
    }
  }

  @Test
  public void detect_whenStandaloneNumericCompatEngineBanner_skipsConfigProbePhase()
      throws Exception {
    try (FakeRespServer server =
        new FakeRespServer(
            ImmutableMap.of(
                INFO_SERVER, bulk("# Server\r\nkvrocks_version:2.9.0\r\n"),
                CONFIG_GET_MODULE, "*0\r\n",
                MODULE_LOADEX, "-ERR unknown command 'MODULE'\r\n"))) {
      DetectionReport report = detectSingleFinding(server, "redis");

      assertThat(report.getVulnerability().getSeverity()).isEqualTo(Severity.HIGH);
      assertThat(assessmentText(report)).contains("Engine: kvrocks 2.9.0");
      assertThat(server.commands())
          .containsExactly(INFO_SERVER, CONFIG_GET_MODULE, MODULE_LOADEX)
          .inOrder();
    }
  }

  @Test
  public void detect_whenValkeyVersionWithRedisServerName_reportsCompatEngineSkip()
      throws Exception {
    try (FakeRespServer server =
        new FakeRespServer(
            ImmutableMap.of(
                INFO_SERVER, bulk("# Server\r\nserver_name:redis\r\nvalkey_version:8.0.1\r\n"),
                CONFIG_GET_MODULE, kvArray("enable-module-command", "no")))) {
      DetectionReport report = detectSingleFinding(server, "redis");

      assertThat(report.getVulnerability().getSeverity()).isEqualTo(Severity.HIGH);
      assertThat(assessmentText(report))
          .contains("runtime CONFIG SET probe skipped for compatibility engine");
      assertThat(server.commands()).containsExactly(INFO_SERVER, CONFIG_GET_MODULE).inOrder();
    }
  }

  @Test
  public void detect_whenUnknownServerNameWithValkeyVersion_skipsConfigProbePhase()
      throws Exception {
    try (FakeRespServer server =
        new FakeRespServer(
            ImmutableMap.of(
                INFO_SERVER,
                    bulk("# Server\r\nserver_name:custom-kv\r\nvalkey_version:8.0.0\r\n"),
                CONFIG_GET_MODULE, "*0\r\n",
                MODULE_LOADEX, "-ERR unknown command 'MODULE'\r\n"))) {
      DetectionReport report = detectSingleFinding(server, "redis");

      assertThat(report.getVulnerability().getMainId().getValue())
          .isEqualTo("REDIS_UNAUTHENTICATED_READ_WRITE_ACCESS");
      assertThat(assessmentText(report)).contains("Engine: custom-kv 8.0.0");
      assertThat(server.commands())
          .containsExactly(INFO_SERVER, CONFIG_GET_MODULE, MODULE_LOADEX)
          .inOrder();
    }
  }

  @Test
  public void detect_whenUnknownServerNameWithRedisVersionOnly_skipsConfigProbePhase()
      throws Exception {
    try (FakeRespServer server =
        new FakeRespServer(
            ImmutableMap.of(
                INFO_SERVER, bulk("# Server\r\nserver_name:custom-kv\r\nredis_version:7.2.5\r\n"),
                CONFIG_GET_MODULE, "*0\r\n",
                MODULE_LOADEX, "-ERR unknown command 'MODULE'\r\n"))) {
      DetectionReport report = detectSingleFinding(server, "redis");

      assertThat(report.getVulnerability().getSeverity()).isEqualTo(Severity.HIGH);
      assertThat(assessmentText(report)).contains("Engine: custom-kv 7.2.5");
      assertThat(server.commands())
          .containsExactly(INFO_SERVER, CONFIG_GET_MODULE, MODULE_LOADEX)
          .inOrder();
    }
  }

  @Test
  public void detect_whenSocketClosesAfterDbfilenameRceConfirmed_preservesCriticalRce()
      throws Exception {
    // Omitting CONFIG_GET_MODULE closes the server socket abruptly during the follow-up probe.
    try (FakeRespServer server =
        new FakeRespServer(
            ImmutableMap.of(
                INFO_SERVER, bulk("# Server\r\nredis_version:7.2.5\r\n"),
                CONFIG_GET_PROTECTED, kvArray("enable-protected-configs", "yes"),
                CONFIG_SET_DBFILENAME, "-ERR dbfilename can't be a path, just a filename\r\n"))) {
      DetectionReport report = detectSingleFinding(server, "redis");

      assertThat(report.getVulnerability().getMainId().getValue())
          .isEqualTo("REDIS_UNAUTHENTICATED_COMMAND_EXECUTION");
      assertThat(report.getVulnerability().getSeverity()).isEqualTo(Severity.CRITICAL);
      assertThat(assessmentText(report)).contains("CONFIG SET dir/dbfilename permitted");
      assertNoMutatingCommands(server.commands());
    }
  }

  @Test
  public void detect_whenFollowUpProbeDisconnectsAfterInfoServer_fallsBackToHighReadWrite()
      throws Exception {
    try (FakeRespServer server =
        new FakeRespServer(
            ImmutableMap.of(INFO_SERVER, bulk("# Server\r\nredis_version:7.2.5\r\n")))) {
      DetectionReport report = detectSingleFinding(server, "redis");

      assertThat(report.getVulnerability().getMainId().getValue())
          .isEqualTo("REDIS_UNAUTHENTICATED_READ_WRITE_ACCESS");
      assertThat(report.getVulnerability().getSeverity()).isEqualTo(Severity.HIGH);
      assertThat(assessmentText(report))
          .contains("follow-up OS RCE configuration probes were interrupted before completion");
      assertNoMutatingCommands(server.commands());
    }
  }

  @Test
  public void detect_whenSslSocketCloseThrowsAfterVerification_preservesCriticalFinding()
      throws Exception {
    Socket plainSocket = mock(Socket.class);
    SSLSocket sslSocket = mock(SSLSocket.class);
    ByteArrayOutputStream capturedOut = new ByteArrayOutputStream();
    when(socketFactoryMock.createSocket(
            eq("127.0.0.1"), eq(6380), eq(EXPECTED_SESSION_TIMEOUT), eq(EXPECTED_SESSION_TIMEOUT)))
        .thenReturn(plainSocket);
    when(socketFactoryMock.wrapWithSsl(eq(plainSocket), eq("127.0.0.1"), eq(6380), eq(true)))
        .thenReturn(sslSocket);
    when(sslSocket.getOutputStream()).thenReturn(new BufferedOutputStream(capturedOut));
    when(sslSocket.getInputStream())
        .thenReturn(
            new ByteArrayInputStream(
                (bulk("# Server\r\nredis_version:7.2.5\r\n")
                        + kvArray("enable-protected-configs", "yes")
                        + "-ERR dbfilename can't be a path, just a filename\r\n"
                        + kvArray("enable-module-command", "no"))
                    .getBytes(UTF_8)));
    doThrow(new IOException("Connection reset during TLS close_notify")).when(sslSocket).close();

    DetectionReportList reports =
        detector.detect(
            TargetInfo.getDefaultInstance(), ImmutableList.of(tcpService("rediss", 6380)));

    assertThat(reports.getDetectionReportsList()).hasSize(1);
    assertThat(reports.getDetectionReports(0).getVulnerability().getSeverity())
        .isEqualTo(Severity.CRITICAL);
    assertNoMutatingCommands(parseRecordedWireCommands(capturedOut.toByteArray()));
  }

  @Test
  public void detect_whenWrapWithSslThrows_closesPlainSocketAndReturnsEmpty() throws Exception {
    Socket plainSocket = mock(Socket.class);
    when(socketFactoryMock.createSocket(
            eq("127.0.0.1"), eq(6380), eq(EXPECTED_SESSION_TIMEOUT), eq(EXPECTED_SESSION_TIMEOUT)))
        .thenReturn(plainSocket);
    when(socketFactoryMock.wrapWithSsl(eq(plainSocket), eq("127.0.0.1"), eq(6380), eq(true)))
        .thenThrow(new SocketTimeoutException("TLS handshake timed out"));

    DetectionReportList reports =
        detector.detect(
            TargetInfo.getDefaultInstance(), ImmutableList.of(tcpService("rediss", 6380)));

    assertThat(reports.getDetectionReportsList()).isEmpty();
    verify(plainSocket).close();
  }

  @Test
  public void detect_whenIpHostnamePortServiceWithTls_dialsIpAndUsesHostnameForSni()
      throws Exception {
    Socket plainSocket = mock(Socket.class);
    SSLSocket sslSocket = mock(SSLSocket.class);
    ByteArrayOutputStream capturedOut = new ByteArrayOutputStream();
    when(socketFactoryMock.createSocket(
            eq("127.0.0.1"), eq(6380), eq(EXPECTED_SESSION_TIMEOUT), eq(EXPECTED_SESSION_TIMEOUT)))
        .thenReturn(plainSocket);
    when(socketFactoryMock.wrapWithSsl(
            eq(plainSocket), eq("redis.internal.example"), eq(6380), eq(true)))
        .thenReturn(sslSocket);
    when(sslSocket.getOutputStream()).thenReturn(new BufferedOutputStream(capturedOut));
    when(sslSocket.getInputStream())
        .thenReturn(
            new ByteArrayInputStream(
                (bulk("# Server\r\nredis_version:7.2.5\r\n")
                        + kvArray("enable-protected-configs", "no")
                        + kvArray("enable-module-command", "no"))
                    .getBytes(UTF_8)));
    NetworkService ipHostnameTlsService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(forIpHostnameAndPort("127.0.0.1", "redis.internal.example", 6380))
            .setServiceName("rediss")
            .setTransportProtocol(TransportProtocol.TCP)
            .build();

    DetectionReportList reports =
        detector.detect(TargetInfo.getDefaultInstance(), ImmutableList.of(ipHostnameTlsService));

    assertThat(reports.getDetectionReportsList()).hasSize(1);
    assertThat(reports.getDetectionReports(0).getVulnerability().getSeverity())
        .isEqualTo(Severity.HIGH);
    verify(socketFactoryMock)
        .createSocket(
            eq("127.0.0.1"), eq(6380), eq(EXPECTED_SESSION_TIMEOUT), eq(EXPECTED_SESSION_TIMEOUT));
    verify(socketFactoryMock)
        .wrapWithSsl(eq(plainSocket), eq("redis.internal.example"), eq(6380), eq(true));
    assertThat(parseRecordedWireCommands(capturedOut.toByteArray()))
        .containsExactly(INFO_SERVER, CONFIG_GET_PROTECTED, CONFIG_GET_MODULE)
        .inOrder();
  }

  @Test
  public void detect_whenHostnamePortService_dialsHostname() throws Exception {
    Socket socket = mock(Socket.class);
    ByteArrayOutputStream capturedOut = new ByteArrayOutputStream();
    when(socketFactoryMock.createSocket(
            eq("redis.internal.example"),
            eq(6379),
            eq(EXPECTED_SESSION_TIMEOUT),
            eq(EXPECTED_SESSION_TIMEOUT)))
        .thenReturn(socket);
    when(socket.getOutputStream()).thenReturn(new BufferedOutputStream(capturedOut));
    when(socket.getInputStream())
        .thenReturn(
            new ByteArrayInputStream(
                (bulk("# Server\r\nredis_version:7.2.5\r\n")
                        + kvArray("enable-protected-configs", "no")
                        + kvArray("enable-module-command", "no"))
                    .getBytes(UTF_8)));
    NetworkService hostnameService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(forHostnameAndPort("redis.internal.example", 6379))
            .setServiceName("redis")
            .setTransportProtocol(TransportProtocol.TCP)
            .build();

    DetectionReportList reports =
        detector.detect(TargetInfo.getDefaultInstance(), ImmutableList.of(hostnameService));

    assertThat(reports.getDetectionReportsList()).hasSize(1);
    assertThat(reports.getDetectionReports(0).getVulnerability().getSeverity())
        .isEqualTo(Severity.HIGH);
    verify(socketFactoryMock)
        .createSocket(
            eq("redis.internal.example"),
            eq(6379),
            eq(EXPECTED_SESSION_TIMEOUT),
            eq(EXPECTED_SESSION_TIMEOUT));
    assertThat(parseRecordedWireCommands(capturedOut.toByteArray()))
        .containsExactly(INFO_SERVER, CONFIG_GET_PROTECTED, CONFIG_GET_MODULE)
        .inOrder();
  }

  @Test
  public void detect_whenRedissService_opensSslSocketAndSendsOrderedProbes() throws Exception {
    ByteArrayOutputStream capturedOut =
        configureMockSslSocket(
            6380,
            bulk("# Server\r\nredis_version:7.2.5\r\n")
                + kvArray("enable-protected-configs", "no")
                + kvArray("enable-module-command", "no"));

    DetectionReportList reports =
        detector.detect(
            TargetInfo.getDefaultInstance(), ImmutableList.of(tcpService("rediss", 6380)));

    assertThat(reports.getDetectionReportsList()).hasSize(1);
    assertThat(reports.getDetectionReports(0).getVulnerability().getSeverity())
        .isEqualTo(Severity.HIGH);
    verify(socketFactoryMock)
        .createSocket(
            eq("127.0.0.1"), eq(6380), eq(EXPECTED_SESSION_TIMEOUT), eq(EXPECTED_SESSION_TIMEOUT));
    verify(socketFactoryMock).wrapWithSsl(any(Socket.class), eq("127.0.0.1"), eq(6380), eq(true));
    verify(socketFactoryMock, never())
        .createSslSocket(anyString(), anyInt(), any(Duration.class), any(Duration.class));
    ImmutableList<ImmutableList<String>> sent =
        parseRecordedWireCommands(capturedOut.toByteArray());
    assertThat(sent)
        .containsExactly(INFO_SERVER, CONFIG_GET_PROTECTED, CONFIG_GET_MODULE)
        .inOrder();
    assertNoMutatingCommands(sent);
  }

  @Test
  public void detect_whenSslValkeyTunnelService_opensSslSocket() throws Exception {
    ByteArrayOutputStream capturedOut =
        configureMockSslSocket(
            6380,
            bulk("# Server\r\nvalkey_version:8.0.1\r\n")
                + kvArray("enable-protected-configs", "no")
                + kvArray("enable-module-command", "no"));

    DetectionReportList reports =
        detector.detect(
            TargetInfo.getDefaultInstance(), ImmutableList.of(tcpService("ssl/valkey", 6380)));

    assertThat(reports.getDetectionReportsList()).hasSize(1);
    assertThat(reports.getDetectionReports(0).getVulnerability().getSeverity())
        .isEqualTo(Severity.HIGH);
    verify(socketFactoryMock)
        .createSocket(
            eq("127.0.0.1"), eq(6380), eq(EXPECTED_SESSION_TIMEOUT), eq(EXPECTED_SESSION_TIMEOUT));
    verify(socketFactoryMock).wrapWithSsl(any(Socket.class), eq("127.0.0.1"), eq(6380), eq(true));
    verify(socketFactoryMock, never())
        .createSslSocket(anyString(), anyInt(), any(Duration.class), any(Duration.class));
    assertThat(parseRecordedWireCommands(capturedOut.toByteArray()))
        .containsExactly(INFO_SERVER, CONFIG_GET_PROTECTED, CONFIG_GET_MODULE)
        .inOrder();
  }

  @Test
  public void detect_whenSupportedSslVersionsPresent_opensSslSocket() throws Exception {
    ByteArrayOutputStream capturedOut =
        configureMockSslSocket(
            6379,
            bulk("# Server\r\nredis_version:7.2.5\r\n")
                + kvArray("enable-protected-configs", "no")
                + kvArray("enable-module-command", "no"));
    NetworkService tlsRedis =
        tcpService("redis", 6379).toBuilder().addSupportedSslVersions("TLSv1.3").build();

    DetectionReportList reports =
        detector.detect(TargetInfo.getDefaultInstance(), ImmutableList.of(tlsRedis));

    assertThat(reports.getDetectionReportsList()).hasSize(1);
    verify(socketFactoryMock)
        .createSocket(
            eq("127.0.0.1"), eq(6379), eq(EXPECTED_SESSION_TIMEOUT), eq(EXPECTED_SESSION_TIMEOUT));
    verify(socketFactoryMock).wrapWithSsl(any(Socket.class), eq("127.0.0.1"), eq(6379), eq(true));
    verify(socketFactoryMock, never())
        .createSslSocket(anyString(), anyInt(), any(Duration.class), any(Duration.class));
    assertThat(parseRecordedWireCommands(capturedOut.toByteArray()))
        .containsExactly(INFO_SERVER, CONFIG_GET_PROTECTED, CONFIG_GET_MODULE)
        .inOrder();
  }

  @Test
  public void detect_whenTcpwrappedOnDefaultPortOrUnspecifiedTransport_probesTarget()
      throws Exception {
    ByteArrayOutputStream capturedOut =
        configureMockSocket(
            bulk("# Server\r\nredis_version:7.2.5\r\n")
                + kvArray("enable-protected-configs", "no")
                + kvArray("enable-module-command", "no"));
    NetworkService tcpwrapped6379 =
        tcpService("tcpwrapped", 6379).toBuilder()
            .setTransportProtocol(TransportProtocol.TRANSPORT_PROTOCOL_UNSPECIFIED)
            .build();

    DetectionReportList reports =
        detector.detect(TargetInfo.getDefaultInstance(), ImmutableList.of(tcpwrapped6379));

    assertThat(reports.getDetectionReportsList()).hasSize(1);
    assertThat(reports.getDetectionReports(0).getVulnerability().getSeverity())
        .isEqualTo(Severity.HIGH);
    assertNoMutatingCommands(parseRecordedWireCommands(capturedOut.toByteArray()));
  }

  @Test
  public void detect_whenInfoExcerptExceeds512CharsAtSurrogateBoundary_truncatesCleanly()
      throws Exception {
    String prefix = "# Server\r\nredis_version:7.2.5\r\n";
    String padding = "a".repeat(511 - prefix.length());
    // U+1F600 is a UTF-16 surrogate pair straddling index 511/512.
    String longInfo = prefix + padding + "\uD83D\uDE00tail";
    ByteArrayOutputStream capturedOut =
        configureMockSocket(
            bulk(longInfo)
                + kvArray("enable-protected-configs", "no")
                + kvArray("enable-module-command", "no"));

    DetectionReportList reports = detectOnDefaultPort();

    assertThat(reports.getDetectionReportsList()).hasSize(1);
    String excerpt = infoExcerptText(reports.getDetectionReports(0));
    assertThat(excerpt).hasLength(511);
    assertThat(Character.isHighSurrogate(excerpt.charAt(excerpt.length() - 1))).isFalse();
    assertNoMutatingCommands(parseRecordedWireCommands(capturedOut.toByteArray()));
  }

  @Test
  public void detect_whenConfigGetReturnsMixedOrNullArrays_drainsStreamCleanly() throws Exception {
    // *4 with bulk strings interleaved with +OK and :1 (CONFIG_GET_PROTECTED) and *-1 null array
    // (CONFIG_GET_MODULE) must both drain cleanly and reject the mixed array before MODULE_LOADEX
    // confirms CRITICAL RCE.
    ByteArrayOutputStream capturedOut =
        configureMockSocket(
            bulk("# Server\r\nredis_version:7.2.5\r\n")
                + "*4\r\n"
                + bulk("enable-protected-configs")
                + "+OK\r\n:1\r\n"
                + bulk("no")
                + "-ERR Can't set immutable config 'dbfilename'\r\n"
                + "*-1\r\n"
                + "-ERR Error loading the extension. Please check the server logs.\r\n");

    DetectionReportList reports = detectOnDefaultPort();

    assertThat(reports.getDetectionReportsList()).hasSize(1);
    assertThat(reports.getDetectionReports(0).getVulnerability().getSeverity())
        .isEqualTo(Severity.CRITICAL);
    assertThat(assessmentText(reports.getDetectionReports(0))).contains("MODULE LOADEX permitted");
    assertThat(parseRecordedWireCommands(capturedOut.toByteArray()))
        .containsExactly(
            INFO_SERVER,
            CONFIG_GET_PROTECTED,
            CONFIG_SET_DBFILENAME,
            CONFIG_GET_MODULE,
            MODULE_LOADEX)
        .inOrder();
  }

  @Test
  public void detect_whenCumulativeRepliesExceed64KiBBudget_fallsBackToHighReadWrite()
      throws Exception {
    // Follow-up RCE-confirming reply appended after largeConfigReply ensures raising
    // MAX_SESSION_BYTES would emit CRITICAL instead of aborting at CONFIG_GET_PROTECTED.
    String infoPayload = "# Server\r\nredis_version:7.2.5\r\n" + "a".repeat(65000);
    String largeConfigReply = "*2\r\n" + bulk("enable-protected-configs") + bulk("x".repeat(600));
    ByteArrayOutputStream capturedOut =
        configureMockSocket(
            bulk(infoPayload)
                + largeConfigReply
                + "-ERR dbfilename can't be a path, just a filename\r\n"
                + kvArray("enable-module-command", "no"));

    DetectionReportList reports = detectOnDefaultPort();

    assertThat(reports.getDetectionReportsList()).hasSize(1);
    assertThat(reports.getDetectionReports(0).getVulnerability().getSeverity())
        .isEqualTo(Severity.HIGH);
    assertThat(assessmentText(reports.getDetectionReports(0)))
        .contains("interrupted before completion");
    assertThat(parseRecordedWireCommands(capturedOut.toByteArray()))
        .containsExactly(INFO_SERVER, CONFIG_GET_PROTECTED)
        .inOrder();
  }

  @Test
  public void detect_whenCumulativeRepliesMatchExact64KiBBudget_completesAllProbes()
      throws Exception {
    String configProtected = kvArray("enable-protected-configs", "no");
    String configModule = kvArray("enable-module-command", "no");
    String prefix = "# Server\r\nredis_version:7.2.5\r\n";
    int targetInfoWireBytes =
        65536 - configProtected.getBytes(UTF_8).length - configModule.getBytes(UTF_8).length;
    // "$65443\r\n" (8 bytes) + payload + "\r\n" (2 bytes) = targetInfoWireBytes.
    int payloadBytes = targetInfoWireBytes - 10;
    String infoPayload = prefix + "a".repeat(payloadBytes - prefix.length());
    String fullWire = bulk(infoPayload) + configProtected + configModule;
    assertThat(fullWire.getBytes(UTF_8)).hasLength(65536);

    ByteArrayOutputStream capturedOut = configureMockSocket(fullWire);
    DetectionReportList reports = detectOnDefaultPort();

    assertThat(reports.getDetectionReportsList()).hasSize(1);
    assertThat(reports.getDetectionReports(0).getVulnerability().getSeverity())
        .isEqualTo(Severity.HIGH);
    assertThat(assessmentText(reports.getDetectionReports(0)))
        .contains("direct OS RCE gates (protected configs and module loading) are locked");
    assertThat(parseRecordedWireCommands(capturedOut.toByteArray()))
        .containsExactly(INFO_SERVER, CONFIG_GET_PROTECTED, CONFIG_GET_MODULE)
        .inOrder();
  }

  @Test
  public void detect_whenConfigGetReturnsNestedArray_fallsBackToHighReadWrite() throws Exception {
    ByteArrayOutputStream capturedOut =
        configureMockSocket(
            bulk("# Server\r\nredis_version:7.2.5\r\n")
                + "*1\r\n*1\r\n+OK\r\n"
                + "-ERR dbfilename can't be a path, just a filename\r\n"
                + kvArray("enable-module-command", "no"));

    DetectionReportList reports = detectOnDefaultPort();

    assertThat(reports.getDetectionReportsList()).hasSize(1);
    assertThat(reports.getDetectionReports(0).getVulnerability().getSeverity())
        .isEqualTo(Severity.HIGH);
    assertThat(assessmentText(reports.getDetectionReports(0)))
        .contains("interrupted before completion");
    assertThat(parseRecordedWireCommands(capturedOut.toByteArray()))
        .containsExactly(INFO_SERVER, CONFIG_GET_PROTECTED)
        .inOrder();
  }

  @Test
  public void detect_whenConfigGetReturnsOversizedArray_fallsBackToHighReadWrite()
      throws Exception {
    ByteArrayOutputStream capturedOut =
        configureMockSocket(
            bulk("# Server\r\nredis_version:7.2.5\r\n")
                + "*17\r\n"
                + "$1\r\na\r\n".repeat(17)
                + "-ERR dbfilename can't be a path, just a filename\r\n"
                + kvArray("enable-module-command", "no"));

    DetectionReportList reports = detectOnDefaultPort();

    assertThat(reports.getDetectionReportsList()).hasSize(1);
    assertThat(reports.getDetectionReports(0).getVulnerability().getSeverity())
        .isEqualTo(Severity.HIGH);
    assertThat(assessmentText(reports.getDetectionReports(0)))
        .contains("interrupted before completion");
    assertThat(parseRecordedWireCommands(capturedOut.toByteArray()))
        .containsExactly(INFO_SERVER, CONFIG_GET_PROTECTED)
        .inOrder();
  }

  @Test
  public void detect_whenRespLineExceeds4KiB_fallsBackToHighReadWrite() throws Exception {
    ByteArrayOutputStream capturedOut =
        configureMockSocket(
            bulk("# Server\r\nredis_version:7.2.5\r\n")
                + "-ERR "
                + "x".repeat(4097)
                + "\r\n"
                + "-ERR dbfilename can't be a path, just a filename\r\n"
                + kvArray("enable-module-command", "no"));

    DetectionReportList reports = detectOnDefaultPort();

    assertThat(reports.getDetectionReportsList()).hasSize(1);
    assertThat(reports.getDetectionReports(0).getVulnerability().getSeverity())
        .isEqualTo(Severity.HIGH);
    assertThat(assessmentText(reports.getDetectionReports(0)))
        .contains("interrupted before completion");
    assertThat(parseRecordedWireCommands(capturedOut.toByteArray()))
        .containsExactly(INFO_SERVER, CONFIG_GET_PROTECTED)
        .inOrder();
  }

  @Test
  public void detect_whenRespLineHasBareLf_fallsBackToHighReadWrite() throws Exception {
    ByteArrayOutputStream capturedOut =
        configureMockSocket(
            bulk("# Server\r\nredis_version:7.2.5\r\n")
                + "-ERR bare lf\n"
                + "-ERR dbfilename can't be a path, just a filename\r\n"
                + kvArray("enable-module-command", "no"));

    DetectionReportList reports = detectOnDefaultPort();

    assertThat(reports.getDetectionReportsList()).hasSize(1);
    assertThat(reports.getDetectionReports(0).getVulnerability().getSeverity())
        .isEqualTo(Severity.HIGH);
    assertThat(assessmentText(reports.getDetectionReports(0)))
        .contains("interrupted before completion");
    assertThat(parseRecordedWireCommands(capturedOut.toByteArray()))
        .containsExactly(INFO_SERVER, CONFIG_GET_PROTECTED)
        .inOrder();
  }

  @Test
  public void detect_whenRespLineHasCrWithoutLf_fallsBackToHighReadWrite() throws Exception {
    ByteArrayOutputStream capturedOut =
        configureMockSocket(
            bulk("# Server\r\nredis_version:7.2.5\r\n")
                + "-ERR missing lf\rX\r\n"
                + "-ERR dbfilename can't be a path, just a filename\r\n"
                + kvArray("enable-module-command", "no"));

    DetectionReportList reports = detectOnDefaultPort();

    assertThat(reports.getDetectionReportsList()).hasSize(1);
    assertThat(reports.getDetectionReports(0).getVulnerability().getSeverity())
        .isEqualTo(Severity.HIGH);
    assertThat(assessmentText(reports.getDetectionReports(0)))
        .contains("interrupted before completion");
    assertThat(parseRecordedWireCommands(capturedOut.toByteArray()))
        .containsExactly(INFO_SERVER, CONFIG_GET_PROTECTED)
        .inOrder();
  }

  @Test
  public void detect_whenRequiresAuthentication_returnsEmptyAndSendsOnlyInfoServer()
      throws Exception {
    ByteArrayOutputStream capturedOut = configureMockSocket("-NOAUTH Authentication required.\r\n");

    assertThat(detectOnDefaultPort().getDetectionReportsList()).isEmpty();
    assertThat(parseRecordedWireCommands(capturedOut.toByteArray())).containsExactly(INFO_SERVER);
  }

  @Test
  public void detect_whenSimpleStringHoneypotBanner_returnsEmpty() throws Exception {
    ByteArrayOutputStream capturedOut = configureMockSocket("+OK redis_version:7.2.5\r\n");

    assertThat(detectOnDefaultPort().getDetectionReportsList()).isEmpty();
    assertThat(parseRecordedWireCommands(capturedOut.toByteArray())).containsExactly(INFO_SERVER);
  }

  @Test
  public void detect_whenNonRedisBanner_returnsEmpty() throws Exception {
    ByteArrayOutputStream capturedOut =
        configureMockSocket(bulk("# Server\r\nnon_redis_version:6.0.15\r\n"));

    assertThat(detectOnDefaultPort().getDetectionReportsList()).isEmpty();
    assertThat(parseRecordedWireCommands(capturedOut.toByteArray())).containsExactly(INFO_SERVER);
  }

  @Test
  public void detect_whenSingleBulkFrameExceeds64KiB_returnsEmpty() throws Exception {
    String prefix = "# Server\r\nredis_version:7.2.5\r\n";
    String oversizedPayload = prefix + "a".repeat(65537 - prefix.length());
    ByteArrayOutputStream capturedOut = configureMockSocket(bulk(oversizedPayload));

    assertThat(detectOnDefaultPort().getDetectionReportsList()).isEmpty();
    assertThat(parseRecordedWireCommands(capturedOut.toByteArray())).containsExactly(INFO_SERVER);
  }

  @Test
  public void detect_whenNullBulkInfoReply_returnsEmpty() throws Exception {
    ByteArrayOutputStream capturedOut = configureMockSocket("$-1\r\n");

    assertThat(detectOnDefaultPort().getDetectionReportsList()).isEmpty();
    assertThat(parseRecordedWireCommands(capturedOut.toByteArray())).containsExactly(INFO_SERVER);
  }

  @Test
  public void detect_whenBulkStringMissingTrailingCr_returnsEmpty() throws Exception {
    String payload = "# Server\r\nredis_version:7.2.5\r\n";
    ByteArrayOutputStream capturedOut =
        configureMockSocket("$" + payload.getBytes(UTF_8).length + "\r\n" + payload + "XX");

    assertThat(detectOnDefaultPort().getDetectionReportsList()).isEmpty();
    assertThat(parseRecordedWireCommands(capturedOut.toByteArray())).containsExactly(INFO_SERVER);
  }

  @Test
  public void detect_whenBulkStringMissingTrailingLf_returnsEmpty() throws Exception {
    String payload = "# Server\r\nredis_version:7.2.5\r\n";
    ByteArrayOutputStream capturedOut =
        configureMockSocket("$" + payload.getBytes(UTF_8).length + "\r\n" + payload + "\rX");

    assertThat(detectOnDefaultPort().getDetectionReportsList()).isEmpty();
    assertThat(parseRecordedWireCommands(capturedOut.toByteArray())).containsExactly(INFO_SERVER);
  }

  @Test
  public void detect_whenTruncatedBulkPayload_returnsEmpty() throws Exception {
    ByteArrayOutputStream capturedOut = configureMockSocket("$31\r\n# Server\r\n");

    assertThat(detectOnDefaultPort().getDetectionReportsList()).isEmpty();
    assertThat(parseRecordedWireCommands(capturedOut.toByteArray())).containsExactly(INFO_SERVER);
  }

  @Test
  public void detect_whenEmptyEof_returnsEmpty() throws Exception {
    ByteArrayOutputStream capturedOut = configureMockSocket("");

    assertThat(detectOnDefaultPort().getDetectionReportsList()).isEmpty();
    assertThat(parseRecordedWireCommands(capturedOut.toByteArray())).containsExactly(INFO_SERVER);
  }

  @Test
  public void detect_setsBoundedSoTimeoutAndHandlesReadTimeout() throws Exception {
    Socket timeoutSocket = mock(Socket.class);
    ByteArrayOutputStream capturedOut = new ByteArrayOutputStream();
    when(socketFactoryMock.createSocket(
            eq("127.0.0.1"), eq(6379), eq(EXPECTED_SESSION_TIMEOUT), eq(EXPECTED_SESSION_TIMEOUT)))
        .thenReturn(timeoutSocket);
    when(timeoutSocket.getOutputStream()).thenReturn(capturedOut);
    InputStream timeoutInput =
        new InputStream() {
          @Override
          public int read() throws IOException {
            throw new SocketTimeoutException("timed out");
          }
        };
    when(timeoutSocket.getInputStream()).thenReturn(timeoutInput);

    assertThat(detectOnDefaultPort().getDetectionReportsList()).isEmpty();
    verify(socketFactoryMock)
        .createSocket(
            eq("127.0.0.1"), eq(6379), eq(EXPECTED_SESSION_TIMEOUT), eq(EXPECTED_SESSION_TIMEOUT));
    verify(timeoutSocket, atLeastOnce()).setSoTimeout(intThat(ms -> ms > 0 && ms <= 5000));
    assertThat(parseRecordedWireCommands(capturedOut.toByteArray())).containsExactly(INFO_SERVER);
  }

  @Test
  public void detect_whenSessionDeadlineExpiresDuringFollowUp_fallsBackToHighReadWrite()
      throws Exception {
    AtomicLong fakeNanos = new AtomicLong(1_000_000_000L);
    Socket socket = mock(Socket.class);
    ByteArrayOutputStream capturedOut = new ByteArrayOutputStream();
    when(socketFactoryMock.createSocket(
            eq("127.0.0.1"), eq(6379), eq(EXPECTED_SESSION_TIMEOUT), eq(EXPECTED_SESSION_TIMEOUT)))
        .thenReturn(socket);
    when(socket.getOutputStream()).thenReturn(capturedOut);
    String infoWire = bulk("# Server\r\nredis_version:7.2.5\r\n");
    ImmutableList<byte[]> chunks =
        ImmutableList.of(
            infoWire.substring(0, infoWire.length() - 1).getBytes(UTF_8),
            infoWire.substring(infoWire.length() - 1).getBytes(UTF_8),
            (kvArray("enable-protected-configs", "yes")
                    + "-ERR dbfilename can't be a path, just a filename\r\n"
                    + kvArray("enable-module-command", "no"))
                .getBytes(UTF_8));
    when(socket.getInputStream())
        .thenReturn(
            new InputStream() {
              private int chunkIndex = 0;

              @Override
              public int read() {
                return -1;
              }

              @Override
              public int read(byte[] b, int off, int len) {
                if (chunkIndex >= chunks.size()) {
                  return -1;
                }
                byte[] chunk = chunks.get(chunkIndex++);
                if (chunkIndex == 2) {
                  // Advance clock to the exact deadline as the final byte of INFO server arrives.
                  fakeNanos.addAndGet(EXPECTED_SESSION_TIMEOUT.toNanos());
                }
                int toCopy = Math.min(len, chunk.length);
                System.arraycopy(chunk, 0, b, off, toCopy);
                return toCopy;
              }
            });

    RedisUnauthenticatedCommandExecutionDetector detectorWithFakeClock =
        new RedisUnauthenticatedCommandExecutionDetector(
            fakeUtcClock, socketFactoryMock, fakeNanos::get);
    DetectionReportList reports =
        detectorWithFakeClock.detect(
            TargetInfo.getDefaultInstance(), ImmutableList.of(tcpService("redis", 6379)));

    assertThat(reports.getDetectionReportsList()).hasSize(1);
    assertThat(reports.getDetectionReports(0).getVulnerability().getMainId().getValue())
        .isEqualTo("REDIS_UNAUTHENTICATED_READ_WRITE_ACCESS");
    assertThat(reports.getDetectionReports(0).getVulnerability().getSeverity())
        .isEqualTo(Severity.HIGH);
    assertThat(assessmentText(reports.getDetectionReports(0)))
        .contains("interrupted before completion");
    assertThat(parseRecordedWireCommands(capturedOut.toByteArray())).containsExactly(INFO_SERVER);
  }

  @Test
  public void detect_whenUdpService_skipsWithoutConnecting() {
    NetworkService udpService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(forIpAndPort("127.0.0.1", 6379))
            .setServiceName("redis")
            .setTransportProtocol(TransportProtocol.UDP)
            .build();

    assertThat(
            detector
                .detect(TargetInfo.getDefaultInstance(), ImmutableList.of(udpService))
                .getDetectionReportsList())
        .isEmpty();
    verifyNoInteractions(socketFactoryMock);
  }

  @Test
  public void detect_whenWebServiceLabeledAsRedis_skipsWithoutConnecting() {
    NetworkService webLabeledAsRedis =
        tcpService("redis", 6379).toBuilder().addSupportedHttpMethods("GET").build();

    assertThat(
            detector
                .detect(TargetInfo.getDefaultInstance(), ImmutableList.of(webLabeledAsRedis))
                .getDetectionReportsList())
        .isEmpty();
    verifyNoInteractions(socketFactoryMock);
  }

  @Test
  public void detect_whenUnnamedServiceOnDefaultPort_probesTarget() throws Exception {
    ByteArrayOutputStream capturedOut =
        configureMockSocket(
            bulk("# Server\r\nredis_version:7.2.5\r\n")
                + kvArray("enable-protected-configs", "no")
                + kvArray("enable-module-command", "no"));

    DetectionReportList reports =
        detector.detect(TargetInfo.getDefaultInstance(), ImmutableList.of(tcpService("", 6379)));

    assertThat(reports.getDetectionReportsList()).hasSize(1);
    assertThat(reports.getDetectionReports(0).getVulnerability().getSeverity())
        .isEqualTo(Severity.HIGH);
    assertThat(parseRecordedWireCommands(capturedOut.toByteArray()))
        .containsExactly(INFO_SERVER, CONFIG_GET_PROTECTED, CONFIG_GET_MODULE)
        .inOrder();
  }

  @Test
  public void detect_whenNonDigitCompatBannerWithoutNumericVersions_returnsEmpty()
      throws Exception {
    ByteArrayOutputStream capturedOut =
        configureMockSocket(bulk("# Server\r\ndragonfly_version:dev\r\n"));

    assertThat(detectOnDefaultPort().getDetectionReportsList()).isEmpty();
    assertThat(parseRecordedWireCommands(capturedOut.toByteArray())).containsExactly(INFO_SERVER);
  }

  @Test
  public void detect_whenInvalidPortServicesPresent_skipsInvalidPortsWithoutAbortingScan()
      throws Exception {
    when(socketFactoryMock.createSocket(
            anyString(),
            intThat(port -> port <= 0 || port > 65535),
            any(Duration.class),
            any(Duration.class)))
        .thenThrow(new IllegalArgumentException("Port must be between 1 and 65535"));
    Socket validSocket = mock(Socket.class);
    ByteArrayOutputStream capturedOut = new ByteArrayOutputStream();
    when(socketFactoryMock.createSocket(
            eq("127.0.0.1"), eq(65535), eq(EXPECTED_SESSION_TIMEOUT), eq(EXPECTED_SESSION_TIMEOUT)))
        .thenReturn(validSocket);
    when(validSocket.getOutputStream()).thenReturn(new BufferedOutputStream(capturedOut));
    when(validSocket.getInputStream())
        .thenReturn(
            new ByteArrayInputStream(
                (bulk("# Server\r\nredis_version:7.2.5\r\n")
                        + kvArray("enable-protected-configs", "no")
                        + kvArray("enable-module-command", "no"))
                    .getBytes(UTF_8)));
    NetworkService portZeroRedis = tcpService("redis", 0);
    NetworkService portTooHighRedis =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forIp("127.0.0.1").toBuilder()
                    .setType(NetworkEndpoint.Type.IP_PORT)
                    .setPort(Port.newBuilder().setPortNumber(65536))
                    .build())
            .setServiceName("redis")
            .setTransportProtocol(TransportProtocol.TCP)
            .build();
    NetworkService validMaxPortRedis = tcpService("redis", 65535);

    DetectionReportList reports =
        detector.detect(
            TargetInfo.getDefaultInstance(),
            ImmutableList.of(portZeroRedis, portTooHighRedis, validMaxPortRedis));

    assertThat(reports.getDetectionReportsList()).hasSize(1);
    assertThat(reports.getDetectionReports(0).getNetworkService()).isEqualTo(validMaxPortRedis);
    assertThat(parseRecordedWireCommands(capturedOut.toByteArray()))
        .containsExactly(INFO_SERVER, CONFIG_GET_PROTECTED, CONFIG_GET_MODULE)
        .inOrder();
  }

  @Test
  public void detect_whenNonCandidateOrPortlessService_skipsWithoutConnecting() {
    NetworkService tcpwrappedNon6379 = tcpService("tcpwrapped", 9100);
    NetworkService unnamedNon6379 = tcpService("", 9100);
    NetworkService bareSsl = tcpService("ssl/", 6379);
    NetworkService portlessRedis =
        NetworkService.newBuilder()
            .setNetworkEndpoint(forIp("127.0.0.1"))
            .setServiceName("redis")
            .setTransportProtocol(TransportProtocol.TCP)
            .build();
    NetworkService emptyHostRedis =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                NetworkEndpoint.newBuilder()
                    .setType(NetworkEndpoint.Type.IP_PORT)
                    .setPort(Port.newBuilder().setPortNumber(6379))
                    .build())
            .setServiceName("redis")
            .setTransportProtocol(TransportProtocol.TCP)
            .build();

    assertThat(
            detector
                .detect(
                    TargetInfo.getDefaultInstance(),
                    ImmutableList.of(
                        tcpwrappedNon6379, unnamedNon6379, bareSsl, portlessRedis, emptyHostRedis))
                .getDetectionReportsList())
        .isEmpty();
    verifyNoInteractions(socketFactoryMock);
  }

  private DetectionReport detectSingleFinding(FakeRespServer server, String serviceName)
      throws Exception {
    return detectSingleFinding(server, tcpService(serviceName, server.port()));
  }

  private DetectionReport detectSingleFinding(FakeRespServer server, NetworkService service)
      throws Exception {
    bindFactoryToLoopbackServer(server.port());
    DetectionReportList reports =
        detector.detect(TargetInfo.getDefaultInstance(), ImmutableList.of(service));
    assertThat(reports.getDetectionReportsList()).hasSize(1);
    return reports.getDetectionReports(0);
  }

  private DetectionReportList detectOnDefaultPort() {
    return detector.detect(
        TargetInfo.getDefaultInstance(), ImmutableList.of(tcpService("redis", 6379)));
  }

  private static String assessmentText(DetectionReport report) {
    return report.getVulnerability().getAdditionalDetails(0).getTextData().getText();
  }

  private static String infoExcerptText(DetectionReport report) {
    return report.getVulnerability().getAdditionalDetails(1).getTextData().getText();
  }

  private void assertLoadexFallbackToModuleUnload(String loadexError) throws Exception {
    try (FakeRespServer server =
        new FakeRespServer(
            ImmutableMap.of(
                INFO_SERVER,
                bulk("# Server\r\nredis_version:6.2.14\r\n"),
                CONFIG_GET_PROTECTED,
                kvArray("enable-protected-configs", "no"),
                CONFIG_GET_MODULE,
                "*0\r\n",
                MODULE_LOADEX,
                loadexError,
                MODULE_UNLOAD,
                "-ERR Error unloading module: no such module with that name\r\n"))) {
      DetectionReport report = detectSingleFinding(server, "redis");

      assertThat(report.getVulnerability().getSeverity()).isEqualTo(Severity.CRITICAL);
      assertThat(assessmentText(report)).contains("MODULE LOAD/UNLOAD permitted");
      assertThat(server.commands())
          .containsExactly(
              INFO_SERVER, CONFIG_GET_PROTECTED, CONFIG_GET_MODULE, MODULE_LOADEX, MODULE_UNLOAD)
          .inOrder();
    }
  }

  private ByteArrayOutputStream configureMockSocket(String wireResponse) throws Exception {
    Socket socket = mock(Socket.class);
    ByteArrayOutputStream capturedOut = new ByteArrayOutputStream();
    when(socketFactoryMock.createSocket(
            eq("127.0.0.1"), eq(6379), eq(EXPECTED_SESSION_TIMEOUT), eq(EXPECTED_SESSION_TIMEOUT)))
        .thenReturn(socket);
    when(socket.getOutputStream()).thenReturn(new BufferedOutputStream(capturedOut));
    when(socket.getInputStream()).thenReturn(new ByteArrayInputStream(wireResponse.getBytes(UTF_8)));
    return capturedOut;
  }

  private ByteArrayOutputStream configureMockSslSocket(int port, String wireResponse)
      throws Exception {
    Socket plainSocket = mock(Socket.class);
    SSLSocket sslSocket = mock(SSLSocket.class);
    ByteArrayOutputStream capturedOut = new ByteArrayOutputStream();
    when(socketFactoryMock.createSocket(
            eq("127.0.0.1"), eq(port), eq(EXPECTED_SESSION_TIMEOUT), eq(EXPECTED_SESSION_TIMEOUT)))
        .thenReturn(plainSocket);
    when(socketFactoryMock.wrapWithSsl(eq(plainSocket), eq("127.0.0.1"), eq(port), eq(true)))
        .thenReturn(sslSocket);
    when(sslSocket.getOutputStream()).thenReturn(new BufferedOutputStream(capturedOut));
    when(sslSocket.getInputStream())
        .thenReturn(new ByteArrayInputStream(wireResponse.getBytes(UTF_8)));
    return capturedOut;
  }

  private void bindFactoryToLoopbackServer(int port) throws Exception {
    when(socketFactoryMock.createSocket(
            eq("127.0.0.1"), eq(port), eq(EXPECTED_SESSION_TIMEOUT), eq(EXPECTED_SESSION_TIMEOUT)))
        .thenAnswer(invocation -> {
          int targetPort = invocation.getArgument(1, Integer.class);
          Socket socket = new Socket();
          socket.connect(
              new InetSocketAddress(InetAddress.getLoopbackAddress(), targetPort),
              TEST_SOCKET_TIMEOUT_MS);
          socket.setSoTimeout(TEST_SOCKET_TIMEOUT_MS);
          return socket;
        });
  }

  private static NetworkService tcpService(String serviceName, int port) {
    return NetworkService.newBuilder()
        .setNetworkEndpoint(forIpAndPort("127.0.0.1", port))
        .setServiceName(serviceName)
        .setTransportProtocol(TransportProtocol.TCP)
        .build();
  }

  private static String bulk(String payload) {
    byte[] bytes = payload.getBytes(UTF_8);
    return "$" + bytes.length + "\r\n" + payload + "\r\n";
  }

  private static String kvArray(String key, String val) {
    return "*2\r\n" + bulk(key) + bulk(val);
  }

  private static ImmutableList<ImmutableList<String>> parseRecordedWireCommands(byte[] wireBytes)
      throws IOException {
    BufferedInputStream in = new BufferedInputStream(new ByteArrayInputStream(wireBytes));
    ImmutableList.Builder<ImmutableList<String>> commands = ImmutableList.builder();
    while (true) {
      Optional<ImmutableList<String>> cmd = readRespCommand(in);
      if (cmd.isEmpty()) {
        break;
      }
      commands.add(cmd.get());
    }
    return commands.build();
  }

  private static Optional<ImmutableList<String>> readRespCommand(BufferedInputStream in)
      throws IOException {
    int prefix = in.read();
    if (prefix < 0) {
      return Optional.empty();
    }
    if (prefix != '*') {
      throw new IOException("Expected RESP2 array prefix '*', got: " + prefix);
    }
    int count = Integer.parseInt(readLine(in));
    ImmutableList.Builder<String> args = ImmutableList.builderWithExpectedSize(count);
    for (int i = 0; i < count; i++) {
      if (in.read() != '$') {
        throw new IOException("Expected RESP2 bulk string prefix '$'");
      }
      int len = Integer.parseInt(readLine(in));
      byte[] data = in.readNBytes(len);
      if (data.length != len || in.read() != '\r' || in.read() != '\n') {
        throw new IOException("Truncated RESP2 command argument");
      }
      args.add(new String(data, UTF_8));
    }
    return Optional.of(args.build());
  }

  private static String readLine(BufferedInputStream in) throws IOException {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    while (true) {
      int b = in.read();
      if (b < 0) {
        throw new IOException("Unexpected EOF");
      }
      if (b == '\r') {
        if (in.read() != '\n') {
          throw new IOException("Expected LF after CR");
        }
        return out.toString(UTF_8);
      }
      out.write(b);
    }
  }

  private static void assertNoMutatingCommands(List<ImmutableList<String>> commands) {
    assertThat(commands).isNotEmpty();
    assertThat(ALLOWED_PROBE_COMMANDS).containsAtLeastElementsIn(commands);
  }

  private static final class FakeRespServer implements AutoCloseable {
    private final ServerSocket serverSocket;
    private final Thread serverThread;
    private final CopyOnWriteArrayList<ImmutableList<String>> receivedCommands =
        new CopyOnWriteArrayList<>();
    private volatile Socket acceptedClient;

    FakeRespServer(Map<ImmutableList<String>, String> responses) throws IOException {
      this.serverSocket =
          new ServerSocket(0, SERVER_BACKLOG, InetAddress.getLoopbackAddress());
      this.serverThread =
          new Thread(() -> {
            try (Socket client = serverSocket.accept()) {
              acceptedClient = client;
              client.setSoTimeout(SERVER_CLIENT_TIMEOUT_MS);
              BufferedInputStream in = new BufferedInputStream(client.getInputStream());
              OutputStream out = client.getOutputStream();
              while (true) {
                Optional<ImmutableList<String>> cmd = readRespCommand(in);
                if (cmd.isEmpty()) {
                  break;
                }
                ImmutableList<String> command = cmd.get();
                receivedCommands.add(command);
                String reply = responses.get(command);
                if (reply == null) {
                  break;
                }
                out.write(reply.getBytes(UTF_8));
                out.flush();
              }
            } catch (IOException ignored) {
              // Test socket closed.
            }
          });
      this.serverThread.setDaemon(true);
      this.serverThread.start();
    }

    int port() {
      return serverSocket.getLocalPort();
    }

    List<ImmutableList<String>> commands() {
      return receivedCommands;
    }

    @Override
    public void close() throws Exception {
      serverSocket.close();
      Socket client = acceptedClient;
      if (client != null) {
        client.close();
      }
      serverThread.join(TEST_SOCKET_TIMEOUT_MS);
    }
  }
}
