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

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.common.base.Ascii;
import com.google.common.base.CharMatcher;
import com.google.common.base.Splitter;
import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.common.net.HostAndPort;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkEndpointUtils;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.socket.TsunamiSocketFactory;
import com.google.tsunami.common.time.UtcClock;
import com.google.tsunami.plugin.PluginType;
import com.google.tsunami.plugin.VulnDetector;
import com.google.tsunami.plugin.annotations.ForServiceName;
import com.google.tsunami.plugin.annotations.PluginInfo;
import com.google.tsunami.proto.AdditionalDetail;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkEndpoint;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.TextData;
import com.google.tsunami.proto.TransportProtocol;
import com.google.tsunami.proto.Vulnerability;
import com.google.tsunami.proto.VulnerabilityId;
import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.function.LongSupplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.inject.Inject;

/**
 * Detects unauthenticated Redis and Valkey services, reporting unauthenticated database read/write
 * access ({@code HIGH}) unless live server setup and configuration permit direct OS command
 * execution ({@code CRITICAL}).
 */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "RedisUnauthenticatedCommandExecutionDetector",
    version = "0.3",
    description =
        "Detects unauthenticated Redis and Valkey read/write access and direct OS RCE"
            + " misconfigurations.",
    author = "Oleksii Prokopchuk (prokopchuk@google.com)",
    bootstrapModule = RedisUnauthenticatedCommandExecutionDetectorBootstrapModule.class)
@ForServiceName({
  "redis",
  "valkey",
  "redis-server",
  "rediss",
  "ssl/redis",
  "ssl/valkey",
  "ssl/redis-server",
  "ssl/rediss",
  "ssl/tcpwrapped",
  "tcpwrapped"
})
public final class RedisUnauthenticatedCommandExecutionDetector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private static final String RCE_VULN_ID = "REDIS_UNAUTHENTICATED_COMMAND_EXECUTION";
  private static final String READ_WRITE_VULN_ID = "REDIS_UNAUTHENTICATED_READ_WRITE_ACCESS";

  private static final String RCE_DESCRIPTION =
      "The scanner verified that this Redis/Valkey instance accepts unauthenticated RESP2 commands"
          + " and is configured in a state that permits direct OS remote code execution (RCE) on"
          + " the Redis host:\n"
          + "1. Unprotected runtime file-write configuration (`CONFIG SET dir` / `dbfilename`"
          + " unlocked — default on Redis < 7.0, or when `enable-protected-configs` is set to"
          + " `yes` / reachable `local` on Redis >= 7.0 and Valkey), allowing attackers to write"
          + " arbitrary files (cron jobs, SSH `authorized_keys`, or web shells).\n"
          + "2. Unprotected dynamic module loading (`MODULE LOAD` / `MODULE LOADEX` unlocked —"
          + " default on Redis 4.0–6.2, or when `enable-module-command` is set to `yes` /"
          + " reachable `local` on Redis >= 7.0 and Valkey), allowing execution of native shared"
          + " libraries (for example, staged into `./dump.rdb` via `REPLICAOF` / `SLAVEOF`"
          + " full-resync).\n"
          + "\n"
          + "Verified using strictly non-destructive RESP2 probes (`INFO server`, `CONFIG GET`,"
          + " path-rejected `CONFIG SET dbfilename \"a/b\"`, and syntax-rejected `MODULE LOADEX"
          + " \"\" CONFIG` / nonexistent `MODULE UNLOAD`) without mutating keys, configuration,"
          + " working directory, or loaded modules.";

  private static final String READ_WRITE_DESCRIPTION =
      "The scanner verified that this Redis/Valkey instance accepts unauthenticated RESP2 commands"
          + " (`INFO server`) without confirming unlocked direct OS file-write (`CONFIG SET dir` /"
          + " `dbfilename`) or dynamic module loading (`MODULE LOAD` / `MODULE LOADEX`).\n"
          + "\n"
          + "Security impact and escalation paths:\n"
          + "1. Unauthenticated data read/write and tampering: any network-reachable client can"
          + " read, exfiltrate, modify, or delete keys (`FLUSHALL`), session tokens, and cached"
          + " credentials, or capture live traffic via `MONITOR`.\n"
          + "2. Downstream application RCE via unsafe deserialization: overwriting keys or"
          + " task-queue payloads consumed by workers using Python `pickle` (Celery, RQ, Django),"
          + " Ruby `Marshal` (Sidekiq, Rails), Java serialization/Kryo, or PHP session handlers"
          + " can achieve remote code execution on connected application hosts.\n"
          + "3. Internal network SSRF: when `REPLICAOF` / `SLAVEOF` or `MIGRATE` is permitted,"
          + " attackers can trigger outbound TCP connections from the Redis host to internal VPC"
          + " endpoints.";

  private static final String VULN_RECOMMENDATION =
      "1. Restrict network reachability using VPC firewall rules and bind Redis/Valkey to private"
          + " or loopback interfaces (`bind 127.0.0.1 -::1`, `protected-mode yes`):"
          + " https://redis.io/docs/latest/operate/oss_and_stack/management/security/\n"
          + "2. Require strong authentication via Redis ACLs (`ACL SETUSER` disabling `nopass` on"
          + " `default` and restricting `@admin` / `@dangerous`) or `requirepass`, and enable TLS"
          + " (`tls-port`) on untrusted networks.\n"
          + "3. Keep `enable-protected-configs no` and `enable-module-command no` (the defaults in"
          + " Redis >= 7.0 and Valkey), and avoid unsafe deserialization formats (`pickle`,"
          + " `Marshal`) for Redis-backed caches and queues.";

  private static final int DEFAULT_REDIS_PORT = 6379;
  private static final String SSL_SERVICE_PREFIX = "ssl/";
  private static final Duration SESSION_TIMEOUT = Duration.ofSeconds(5);
  private static final int MAX_INFO_EXCERPT_CHARS = 512;
  private static final String PROBE_NAME = "__tsunami_ro_probe__";
  private static final String DBFILENAME_INVALID_PATH = "a/b";
  private static final Splitter LINE_SPLITTER = Splitter.on('\n');
  private static final CharMatcher ASCII_DIGIT = CharMatcher.inRange('0', '9');
  private static final Pattern REDIS_VERSION_PATTERN = Pattern.compile("([0-9]+)\\.([0-9]+)");

  private final Clock utcClock;
  private final TsunamiSocketFactory socketFactory;
  private final LongSupplier nanoTimeSupplier;

  @Inject
  RedisUnauthenticatedCommandExecutionDetector(
      @UtcClock Clock utcClock, TsunamiSocketFactory socketFactory) {
    this(utcClock, socketFactory, System::nanoTime);
  }

  RedisUnauthenticatedCommandExecutionDetector(
      Clock utcClock, TsunamiSocketFactory socketFactory, LongSupplier nanoTimeSupplier) {
    this.utcClock = checkNotNull(utcClock);
    this.socketFactory = checkNotNull(socketFactory);
    this.nanoTimeSupplier = checkNotNull(nanoTimeSupplier);
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    return DetectionReportList.newBuilder()
        .addAllDetectionReports(
            matchedServices.stream()
                .filter(RedisUnauthenticatedCommandExecutionDetector::isCandidateService)
                .flatMap(networkService ->
                    probeTarget(networkService).stream()
                        .map(outcome -> buildDetectionReport(targetInfo, networkService, outcome)))
                .collect(toImmutableList()))
        .build();
  }

  @Override
  public ImmutableList<Vulnerability> getAdvisories() {
    return ImmutableList.of(buildRceAdvisory(), buildReadWriteAdvisory());
  }

  private static boolean isCandidateService(NetworkService service) {
    if (NetworkServiceUtils.isWebService(service)) {
      return false;
    }
    TransportProtocol protocol = service.getTransportProtocol();
    if (protocol != TransportProtocol.TCP
        && protocol != TransportProtocol.TRANSPORT_PROTOCOL_UNSPECIFIED) {
      return false;
    }
    String name = Ascii.toLowerCase(service.getServiceName().trim());
    // PluginManager routes unnamed ("") services to @ForServiceName detectors; restrict them to
    // the default Redis port consistently with "tcpwrapped" and reject bare "ssl/".
    if (name.isEmpty()) {
      return service.getNetworkEndpoint().getPort().getPortNumber() == DEFAULT_REDIS_PORT;
    }
    if (name.startsWith(SSL_SERVICE_PREFIX)) {
      name = name.substring(SSL_SERVICE_PREFIX.length());
    }
    return switch (name) {
      case "redis", "valkey", "redis-server", "rediss" -> true;
      case "tcpwrapped" ->
          service.getNetworkEndpoint().getPort().getPortNumber() == DEFAULT_REDIS_PORT;
      default -> false;
    };
  }

  private Optional<ProbeOutcome> probeTarget(NetworkService networkService) {
    NetworkEndpoint endpoint = networkService.getNetworkEndpoint();
    if (!NetworkEndpointUtils.hasPort(endpoint)) {
      return Optional.empty();
    }
    int port = endpoint.getPort().getPortNumber();
    if (port <= 0 || port > NetworkEndpointUtils.MAX_PORT_NUMBER) {
      return Optional.empty();
    }
    String dialHost =
        NetworkEndpointUtils.hasIpAddress(endpoint)
            ? endpoint.getIpAddress().getAddress()
            : endpoint.getHostname().getName();
    if (dialHost.isEmpty()) {
      return Optional.empty();
    }
    String sniHost =
        NetworkEndpointUtils.hasHostname(endpoint) ? endpoint.getHostname().getName() : dialHost;
    HostAndPort hp = HostAndPort.fromParts(dialHost, port);
    boolean useTls = useTlsForService(networkService);
    // Retained outside try-with-resources so a Socket.close() IOException (e.g., TLS close_notify
    // reset) caught below does not discard an already-verified finding.
    ProbeOutcome outcome = null;

    try (Socket socket = openSocket(dialHost, sniHost, port, useTls)) {
      RespConnection conn = new RespConnection(socket, SESSION_TIMEOUT, nanoTimeSupplier);
      RespReply infoReply = conn.probe("INFO", "server");
      if (infoReply.type() != RespType.BULK_STRING) {
        return Optional.empty();
      }
      Optional<ServerBanner> parsedBanner = parseServerBanner(infoReply.text());
      if (parsedBanner.isEmpty()) {
        logger.atFine().log(
            "Service at %s did not return a valid Redis/Valkey INFO server response.", hp);
        return Optional.empty();
      }
      outcome = probeRceConfig(conn, parsedBanner.get(), hp);
    } catch (IOException e) {
      logger.atFine().withCause(e).log("Unable to probe or close Redis candidate at %s.", hp);
    }
    return Optional.ofNullable(outcome);
  }

  private Socket openSocket(String dialHost, String sniHost, int port, boolean useTls)
      throws IOException {
    Socket plainSocket =
        socketFactory.createSocket(dialHost, port, SESSION_TIMEOUT, SESSION_TIMEOUT);
    if (!useTls) {
      return plainSocket;
    }
    try {
      return socketFactory.wrapWithSsl(plainSocket, sniHost, port, /* autoClose= */ true);
    } catch (Throwable t) {
      try (plainSocket) {
        throw t;
      }
    }
  }

  private static boolean useTlsForService(NetworkService service) {
    if (service.getSupportedSslVersionsCount() > 0) {
      return true;
    }
    String name = Ascii.toLowerCase(service.getServiceName().trim());
    return name.equals("rediss") || name.startsWith(SSL_SERVICE_PREFIX);
  }

  private static Optional<ServerBanner> parseServerBanner(String info) {
    String redisVersion = "";
    String valkeyVersion = "";
    String compatEngine = "";
    String compatVersion = "";
    String serverName = "";

    for (String rawLine : LINE_SPLITTER.split(info)) {
      String trimmed = rawLine.trim();
      if (trimmed.isEmpty() || trimmed.startsWith("#")) {
        continue;
      }
      int colonIdx = trimmed.indexOf(':');
      if (colonIdx <= 0) {
        continue;
      }
      String key = Ascii.toLowerCase(trimmed.substring(0, colonIdx).trim());
      String val = trimmed.substring(colonIdx + 1).trim();
      switch (key) {
        case "redis_version" -> redisVersion = val;
        case "valkey_version" -> valkeyVersion = val;
        case "server_name" -> serverName = Ascii.toLowerCase(val);
        case "dragonfly_version", "kvrocks_version", "garnet_version", "keydb_version" -> {
          // Record the first compatibility marker even if empty so it fails closed alongside
          // redis_version, upgrading only when gaining a non-empty or digit-bearing version.
          if (compatEngine.isEmpty()
              || (compatVersion.isEmpty() && !val.isEmpty())
              || (!containsAsciiDigit(compatVersion) && containsAsciiDigit(val))) {
            compatEngine = key.substring(0, key.indexOf('_'));
            compatVersion = val;
          }
        }
        default -> {}
      }
    }

    String excerpt = truncateExcerpt(info);
    if (!compatEngine.isEmpty()
        && (containsAsciiDigit(compatVersion)
            || hasLeadingDigit(valkeyVersion)
            || hasLeadingDigit(redisVersion))) {
      // Third-party RESP2 engines (Dragonfly, Kvrocks, Garnet, KeyDB) do not guarantee C Redis's
      // pathIsBaseName check on runtime CONFIG SET dbfilename.
      return Optional.of(
          new ServerBanner(
              compatEngine,
              compatVersion.isEmpty() ? "unknown" : compatVersion,
              excerpt,
              ConfigProbeMode.SKIP_COMPATIBILITY_ENGINE));
    }
    if (hasLeadingDigit(valkeyVersion)) {
      if (!serverName.isEmpty() && !serverName.equals("valkey")) {
        return Optional.of(
            new ServerBanner(
                serverName, valkeyVersion, excerpt, ConfigProbeMode.SKIP_COMPATIBILITY_ENGINE));
      }
      return Optional.of(
          new ServerBanner("valkey", valkeyVersion, excerpt, ConfigProbeMode.DBFILENAME_PATH));
    }
    if (!hasLeadingDigit(redisVersion)) {
      return Optional.empty();
    }
    if (!serverName.isEmpty() && !serverName.equals("redis") && !serverName.equals("valkey")) {
      return Optional.of(
          new ServerBanner(
              serverName, redisVersion, excerpt, ConfigProbeMode.SKIP_COMPATIBILITY_ENGINE));
    }
    // Route parsed Redis >= 3.2 to pathIsBaseName probing, parsed Redis < 3.2 to the synthetic
    // CONFIG SET probe, and unparseable versions fail-closed to SKIP_UNPARSED_VERSION.
    return Optional.of(
        new ServerBanner(
            "redis", redisVersion, excerpt, resolveRedisConfigProbeMode(redisVersion)));
  }

  private static String truncateExcerpt(String text) {
    if (text.length() <= MAX_INFO_EXCERPT_CHARS) {
      return text;
    }
    int end = MAX_INFO_EXCERPT_CHARS;
    if (Character.isHighSurrogate(text.charAt(end - 1))) {
      end--;
    }
    return text.substring(0, end);
  }

  private static ConfigProbeMode resolveRedisConfigProbeMode(String version) {
    Matcher matcher = REDIS_VERSION_PATTERN.matcher(version);
    if (!matcher.lookingAt()) {
      return ConfigProbeMode.SKIP_UNPARSED_VERSION;
    }
    try {
      int major = Integer.parseInt(matcher.group(1));
      int minor = Integer.parseInt(matcher.group(2));
      return (major > 3 || (major == 3 && minor >= 2))
          ? ConfigProbeMode.DBFILENAME_PATH
          : ConfigProbeMode.SYNTHETIC_PARAMETER;
    } catch (NumberFormatException e) {
      return ConfigProbeMode.SKIP_UNPARSED_VERSION;
    }
  }

  private static boolean hasLeadingDigit(String value) {
    return !value.isEmpty() && ASCII_DIGIT.matches(value.charAt(0));
  }

  private static boolean containsAsciiDigit(String value) {
    return ASCII_DIGIT.matchesAnyOf(value);
  }

  private static ProbeOutcome probeRceConfig(
      RespConnection conn, ServerBanner banner, HostAndPort hp) {
    List<String> vectors = new ArrayList<>();
    try {
      // Native Redis >= 3.2 and Valkey evaluate ACL and enable-protected-configs gates before
      // pathIsBaseName rejects "a/b" with "just a filename", confirming CONFIG SET is unlocked
      // without mutating rdb_filename. Legacy Redis < 3.2 uses an unknown parameter name instead.
      if (banner.configMode().shouldProbe()
          && !readConfigOption(conn, "enable-protected-configs").equals("no")) {
        banner.configMode().probeConfigSet(conn).ifPresent(vectors::add);
      }

      // Redis >= 7.0 and Valkey evaluate ACL and enable-module-command before parseLoadexArguments
      // rejects incomplete CONFIG arguments (never invoking dlopen). Only fall back to MODULE
      // UNLOAD when LOADEX is unknown (Redis 4.0-6.2); -NOPERM on LOADEX must not fall back because
      // ACLs may permit UNLOAD while blocking module loading.
      if (!readConfigOption(conn, "enable-module-command").equals("no")) {
        RespReply loadexResp = conn.probe("MODULE", "LOADEX", "", "CONFIG");
        if (loadexResp.isErrorContaining("error loading the extension")) {
          vectors.add("MODULE LOADEX permitted (module loading unlocked)");
        } else if (isUnknownSubcommandError(loadexResp)) {
          RespReply unloadResp = conn.probe("MODULE", "UNLOAD", PROBE_NAME);
          if (unloadResp.isErrorContaining("no such module")) {
            vectors.add("MODULE LOAD/UNLOAD permitted (module commands unlocked)");
          }
        }
      }
      return new ProbeOutcome(banner, ImmutableList.copyOf(vectors), /* probesComplete= */ true);
    } catch (IOException e) {
      // Preserve any already-verified RCE vectors; otherwise fall back to HIGH read/write access
      // because unauthenticated INFO server access was already confirmed.
      logger.atFine().withCause(e).log(
          "Follow-up RCE configuration probe interrupted on %s (verified vectors=%d).",
          hp, vectors.size());
      return new ProbeOutcome(banner, ImmutableList.copyOf(vectors), /* probesComplete= */ false);
    }
  }

  private static boolean isUnknownSubcommandError(RespReply resp) {
    return resp.isErrorContaining("unknown subcommand")
        || resp.isErrorContaining("wrong number of arguments")
        || resp.isErrorContaining("syntax");
  }

  private static String readConfigOption(RespConnection conn, String option) throws IOException {
    RespReply resp = conn.probe("CONFIG", "GET", option);
    if (resp.items().size() == 2 && Ascii.equalsIgnoreCase(resp.items().get(0), option)) {
      return Ascii.toLowerCase(resp.items().get(1).trim());
    }
    return "";
  }

  private DetectionReport buildDetectionReport(
      TargetInfo targetInfo, NetworkService service, ProbeOutcome outcome) {
    Vulnerability.Builder vulnBuilder;
    String summary;
    if (!outcome.rceVectors().isEmpty()) {
      vulnBuilder = buildRceAdvisory().toBuilder();
      summary =
          String.format(
              "Engine: %s %s; verified OS RCE misconfiguration(s): %s.",
              outcome.banner().engine(),
              outcome.banner().version(),
              String.join("; ", outcome.rceVectors()));
    } else {
      vulnBuilder = buildReadWriteAdvisory().toBuilder();
      String gateStatus =
          outcome.probesComplete()
              ? outcome.banner().configMode().lockedGateStatus()
              : "follow-up OS RCE configuration probes were interrupted before completion";
      summary =
          String.format(
              "Engine: %s %s; unauthenticated command access confirmed via INFO server; %s.",
              outcome.banner().engine(), outcome.banner().version(), gateStatus);
    }
    vulnBuilder
        .addAdditionalDetails(
            AdditionalDetail.newBuilder()
                .setDescription("Configuration assessment")
                .setTextData(TextData.newBuilder().setText(summary)))
        .addAdditionalDetails(
            AdditionalDetail.newBuilder()
                .setDescription("INFO server excerpt")
                .setTextData(TextData.newBuilder().setText(outcome.banner().infoExcerpt())));

    return DetectionReport.newBuilder()
        .setTargetInfo(targetInfo)
        .setNetworkService(service)
        .setDetectionTimestamp(Timestamps.fromMillis(utcClock.instant().toEpochMilli()))
        .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
        .setVulnerability(vulnBuilder.build())
        .build();
  }

  private static Vulnerability buildRceAdvisory() {
    return Vulnerability.newBuilder()
        .setMainId(VulnerabilityId.newBuilder().setPublisher("GOOGLE").setValue(RCE_VULN_ID))
        .setSeverity(Severity.CRITICAL)
        .setTitle("Redis unauthenticated command execution")
        .setDescription(RCE_DESCRIPTION)
        .setRecommendation(VULN_RECOMMENDATION)
        .build();
  }

  private static Vulnerability buildReadWriteAdvisory() {
    return Vulnerability.newBuilder()
        .setMainId(
            VulnerabilityId.newBuilder().setPublisher("GOOGLE").setValue(READ_WRITE_VULN_ID))
        .setSeverity(Severity.HIGH)
        .setTitle("Redis unauthenticated read/write and command access")
        .setDescription(READ_WRITE_DESCRIPTION)
        .setRecommendation(VULN_RECOMMENDATION)
        .build();
  }

  private enum ConfigProbeMode {
    SKIP_COMPATIBILITY_ENGINE(
        "runtime CONFIG SET probe skipped for compatibility engine; module loading gate is locked"),
    SKIP_UNPARSED_VERSION(
        "runtime CONFIG SET probe skipped for unparsed Redis version; module loading gate is"
            + " locked"),
    DBFILENAME_PATH(
        "dbfilename",
        DBFILENAME_INVALID_PATH,
        "just a filename",
        "CONFIG SET dir/dbfilename permitted (protected configs unlocked)"),
    SYNTHETIC_PARAMETER(
        PROBE_NAME,
        "",
        "unsupported config parameter",
        "CONFIG SET dir/dbfilename permitted");

    private final String configParam;
    private final String configValue;
    private final String expectedErrorNeedle;
    private final String verifiedVector;
    private final String lockedGateStatus;

    ConfigProbeMode(String lockedGateStatus) {
      this.configParam = "";
      this.configValue = "";
      this.expectedErrorNeedle = "";
      this.verifiedVector = "";
      this.lockedGateStatus = lockedGateStatus;
    }

    ConfigProbeMode(
        String configParam,
        String configValue,
        String expectedErrorNeedle,
        String verifiedVector) {
      this.configParam = configParam;
      this.configValue = configValue;
      this.expectedErrorNeedle = expectedErrorNeedle;
      this.verifiedVector = verifiedVector;
      this.lockedGateStatus =
          "direct OS RCE gates (protected configs and module loading) are locked";
    }

    boolean shouldProbe() {
      return !configParam.isEmpty();
    }

    String lockedGateStatus() {
      return lockedGateStatus;
    }

    Optional<String> probeConfigSet(RespConnection conn) throws IOException {
      if (!shouldProbe()) {
        return Optional.empty();
      }
      RespReply resp = conn.probe("CONFIG", "SET", configParam, configValue);
      return resp.isErrorContaining(expectedErrorNeedle)
          ? Optional.of(verifiedVector)
          : Optional.empty();
    }
  }

  private enum RespType {
    SIMPLE_STRING,
    ERROR,
    INTEGER,
    BULK_STRING,
    NULL_BULK_STRING,
    ARRAY
  }

  private record RespReply(RespType type, String text, ImmutableList<String> items) {
    boolean isErrorContaining(String needle) {
      return type == RespType.ERROR && Ascii.toLowerCase(text).contains(needle);
    }
  }

  private record ServerBanner(
      String engine, String version, String infoExcerpt, ConfigProbeMode configMode) {}

  private record ProbeOutcome(
      ServerBanner banner, ImmutableList<String> rceVectors, boolean probesComplete) {}

  /**
   * Minimal bounded RESP2 wire helper for this detector's INFO, CONFIG, and MODULE probes.
   *
   * <p>Implements only the flat subset of RESP2 returned by those probes (single-line replies, bulk
   * strings, and flat arrays of bulk strings) within a 64 KiB session budget, avoiding a
   * third-party Redis client dependency while keeping TCP streams synchronized and rejecting
   * non-RESP banners.
   */
  private static final class RespConnection {
    private static final int MAX_SESSION_BYTES = 65536;
    private static final int MAX_LINE_BYTES = 4096;
    private static final int MAX_ARRAY_ITEMS = 16;
    private static final int STREAM_BUFFER_BYTES = 4096;
    private static final int INITIAL_LINE_BUFFER_BYTES = 64;
    private static final int CRLF_BYTES = 2;

    private final Socket socket;
    private final BufferedInputStream in;
    private final OutputStream out;
    private final LongSupplier nanoTimeSupplier;
    private final long deadlineNanos;
    private int remainingBytes = MAX_SESSION_BYTES;

    RespConnection(Socket socket, Duration timeout, LongSupplier nanoTimeSupplier)
        throws IOException {
      this.socket = socket;
      this.in = new BufferedInputStream(socket.getInputStream(), STREAM_BUFFER_BYTES);
      this.out = socket.getOutputStream();
      this.nanoTimeSupplier = nanoTimeSupplier;
      this.deadlineNanos = nanoTimeSupplier.getAsLong() + timeout.toNanos();
    }

    RespReply probe(String... args) throws IOException {
      updateSoTimeout();
      ByteArrayOutputStream cmd = new ByteArrayOutputStream();
      cmd.writeBytes(("*" + args.length + "\r\n").getBytes(UTF_8));
      for (String arg : args) {
        byte[] bytes = arg.getBytes(UTF_8);
        cmd.writeBytes(("$" + bytes.length + "\r\n").getBytes(UTF_8));
        cmd.writeBytes(bytes);
        cmd.writeBytes("\r\n".getBytes(UTF_8));
      }
      out.write(cmd.toByteArray());
      out.flush();
      return readReply(/* allowArray= */ true);
    }

    private RespReply readReply(boolean allowArray) throws IOException {
      int prefix = readByte();
      return switch (prefix) {
        case '+' -> new RespReply(RespType.SIMPLE_STRING, readCrLfLine(), ImmutableList.of());
        case '-' -> new RespReply(RespType.ERROR, readCrLfLine(), ImmutableList.of());
        case ':' -> new RespReply(RespType.INTEGER, readCrLfLine(), ImmutableList.of());
        case '$' -> readBulkStringReply();
        case '*' -> {
          if (!allowArray) {
            throw new IOException("Unexpected nested RESP2 array");
          }
          int count = parseLength(readCrLfLine(), MAX_ARRAY_ITEMS);
          if (count < 0) {
            yield new RespReply(RespType.ARRAY, "", ImmutableList.of());
          }
          ImmutableList.Builder<String> items = ImmutableList.builderWithExpectedSize(count);
          boolean allBulkStrings = true;
          for (int i = 0; i < count; i++) {
            // Drain all elements even when non-bulk items appear so the TCP stream stays
            // synchronized for follow-up probes on the same connection.
            RespReply elem = readReply(/* allowArray= */ false);
            if (elem.type() == RespType.BULK_STRING) {
              items.add(elem.text());
            } else {
              allBulkStrings = false;
            }
          }
          yield new RespReply(
              RespType.ARRAY, "", allBulkStrings ? items.build() : ImmutableList.of());
        }
        default -> throw new IOException("Unexpected RESP2 prefix byte: " + prefix);
      };
    }

    private RespReply readBulkStringReply() throws IOException {
      int len = parseLength(readCrLfLine(), Math.max(0, remainingBytes - CRLF_BYTES));
      if (len < 0) {
        return new RespReply(RespType.NULL_BULK_STRING, "", ImmutableList.of());
      }
      byte[] data = new byte[len];
      int off = 0;
      while (off < len) {
        updateSoTimeout();
        int n = in.read(data, off, len - off);
        if (n < 0) {
          throw new IOException("Truncated RESP2 bulk payload");
        }
        off += n;
      }
      remainingBytes -= len;
      if (readByte() != '\r' || readByte() != '\n') {
        throw new IOException("Missing trailing CRLF after RESP2 bulk string");
      }
      return new RespReply(RespType.BULK_STRING, new String(data, UTF_8), ImmutableList.of());
    }

    private String readCrLfLine() throws IOException {
      ByteArrayOutputStream line = new ByteArrayOutputStream(INITIAL_LINE_BUFFER_BYTES);
      while (true) {
        int b = readByte();
        if (b == '\r') {
          if (readByte() != '\n') {
            throw new IOException("Expected LF after CR in RESP2 line");
          }
          return line.toString(UTF_8);
        }
        if (b == '\n' || line.size() >= MAX_LINE_BYTES) {
          throw new IOException("Invalid or oversized RESP2 line");
        }
        line.write(b);
      }
    }

    private int readByte() throws IOException {
      if (remainingBytes <= 0) {
        throw new IOException("RESP2 session byte budget exceeded");
      }
      long remaining = remainingNanos();
      if (in.available() == 0) {
        setSoTimeoutForRemaining(remaining);
      }
      int b = in.read();
      if (b < 0) {
        throw new IOException("Unexpected EOF reading RESP2 frame");
      }
      remainingBytes--;
      return b;
    }

    private long remainingNanos() throws SocketTimeoutException {
      long remaining = deadlineNanos - nanoTimeSupplier.getAsLong();
      if (remaining <= 0) {
        throw new SocketTimeoutException("Redis probe session deadline exceeded");
      }
      return remaining;
    }

    private void updateSoTimeout() throws IOException {
      setSoTimeoutForRemaining(remainingNanos());
    }

    private void setSoTimeoutForRemaining(long remainingNanos) throws IOException {
      long remainingMs = Math.max(1L, TimeUnit.NANOSECONDS.toMillis(remainingNanos));
      socket.setSoTimeout((int) Math.min(remainingMs, Integer.MAX_VALUE));
    }

    private static int parseLength(String raw, int max) throws IOException {
      if (raw.equals("-1")) {
        return -1;
      }
      if (raw.isEmpty() || raw.charAt(0) < '0' || raw.charAt(0) > '9') {
        throw new IOException("Invalid RESP2 length: " + raw);
      }
      try {
        int val = Integer.parseInt(raw);
        if (val < 0 || val > max) {
          throw new IOException("Out-of-bounds RESP2 length: " + val);
        }
        return val;
      } catch (NumberFormatException e) {
        throw new IOException("Invalid RESP2 length: " + raw, e);
      }
    }
  }
}
