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
package com.google.tsunami.plugins.detectors.metabase;

import static com.google.common.truth.extensions.proto.ProtoTruth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostname;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostnameAndPort;

import com.google.common.collect.ImmutableList;
import com.google.inject.Guice;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.common.time.testing.FakeUtcClockModule;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkEndpoint;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.Software;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.TransportProtocol;
import com.google.tsunami.proto.Vulnerability;
import com.google.tsunami.proto.VulnerabilityId;
import java.time.Instant;
import javax.inject.Inject;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Unit tests for {@link MetabaseCve202141277Detector}.
 */
@RunWith(JUnit4.class)
public final class MetabaseCve202141277DetectorTest {

  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2020-01-01T00:00:00.00Z"));

  @Inject
  private MetabaseCve202141277Detector detector;

  private MockWebServer mockWebServer;
  private NetworkService testService;

  @Before
  public void setUp() {
    mockWebServer = new MockWebServer();
    testService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .setTransportProtocol(TransportProtocol.TCP)
            .setSoftware(Software.newBuilder().setName("MetaBase"))
            .setServiceName("http")
            .build();

    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new HttpClientModule.Builder().build(),
            new MetabaseCve202141277DetectorBootstrapModule())
        .injectMembers(this);
  }

  @Test
  public void detect_whenSolrIsVulnerable_reportsVuln() {
    mockWebServer.enqueue(
        new MockResponse().setResponseCode(200).setBody("root:x:0:0:root:/root:/bin/ash\n"
            + "bin:x:1:1:bin:/bin:/sbin/nologin\n"
            + "daemon:x:2:2:daemon:/sbin:/sbin/nologin\n"
            + "adm:x:3:4:adm:/var/adm:/sbin/nologin\n"
            + "lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin\n"
            + "sync:x:5:0:sync:/sbin:/bin/sync\n"
            + "shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown\n"
            + "halt:x:7:0:halt:/sbin:/sbin/halt\n"
            + "mail:x:8:12:mail:/var/mail:/sbin/nologin\n"
            + "news:x:9:13:news:/usr/lib/news:/sbin/nologin\n"
            + "uucp:x:10:14:uucp:/var/spool/uucppublic:/sbin/nologin\n"
            + "operator:x:11:0:operator:/root:/sbin/nologin\n"
            + "man:x:13:15:man:/usr/man:/sbin/nologin\n"
            + "postmaster:x:14:12:postmaster:/var/mail:/sbin/nologin\n"
            + "cron:x:16:16:cron:/var/spool/cron:/sbin/nologin\n"
            + "ftp:x:21:21::/var/lib/ftp:/sbin/nologin\n"
            + "sshd:x:22:22:sshd:/dev/null:/sbin/nologin\n"
            + "at:x:25:25:at:/var/spool/cron/atjobs:/sbin/nologin\n"
            + "squid:x:31:31:Squid:/var/cache/squid:/sbin/nologin\n"
            + "xfs:x:33:33:X Font Server:/etc/X11/fs:/sbin/nologin\n"
            + "games:x:35:35:games:/usr/games:/sbin/nologin\n"
            + "cyrus:x:85:12::/usr/cyrus:/sbin/nologin\n"
            + "vpopmail:x:89:89::/var/vpopmail:/sbin/nologin\n"
            + "ntp:x:123:123:NTP:/var/empty:/sbin/nologin\n"
            + "smmsp:x:209:209:smmsp:/var/spool/mqueue:/sbin/nologin\n"
            + "guest:x:405:100:guest:/dev/null:/sbin/nologin\n"
            + "nobody:x:65534:65534:nobody:/:/sbin/nologin\n"
            + "metabase:x:2000:2000:Linux User,,,:/home/metabase:/bin/ash"));
    mockWebServer.url("/");

    DetectionReportList detectionReports =
        detector.detect(TargetInfo.getDefaultInstance(), ImmutableList.of(testService));

    assertThat(detectionReports.getDetectionReportsList())
        .containsExactly(
            DetectionReport.newBuilder()
                .setTargetInfo(TargetInfo.getDefaultInstance())
                .setNetworkService(testService)
                .setDetectionTimestamp(
                    Timestamps.fromMillis(Instant.now(fakeUtcClock).toEpochMilli()))
                .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
                .setVulnerability(
                    Vulnerability.newBuilder()
                        .setMainId(VulnerabilityId.newBuilder().setPublisher("TSUNAMI_COMMUNITY")
                            .setValue("CVE_2021_41277"))
                        .setSeverity(Severity.CRITICAL)
                        .setTitle("Metabase CVE-2021-41277 Local File Inclusion Vulnerability")
                        .setDescription("Metabase is an open source data analytics platform. In "
                            + "affected versions a security issue has been discovered with the "
                            + "custom GeoJSON map (`admin->settings->maps->custom maps->add a "
                            + "map`) support and potential local file inclusion (including "
                            + "environment variables). URLs were not validated prior to being "
                            + "loaded. This issue is fixed in a new maintenance release (0.40.5 "
                            + "and 1.40.5), and any subsequent release after that.")
                        .setRecommendation("upgrade to latest version")
                ).build()
        );
  }

  @Test
  public void detect_whenSolrIsNotVulnerable_doesNotReportVuln() {
    mockWebServer.enqueue(new MockResponse().setResponseCode(200).setBody(""));
    mockWebServer.url("/");

    assertThat(
        detector
            .detect(
                buildTargetInfo(forHostname(mockWebServer.getHostName())),
                ImmutableList.of(testService))
            .getDetectionReportsList())
        .isEmpty();
  }

  private static TargetInfo buildTargetInfo(NetworkEndpoint networkEndpoint) {
    return TargetInfo.newBuilder().addNetworkEndpoints(networkEndpoint).build();
  }
}
