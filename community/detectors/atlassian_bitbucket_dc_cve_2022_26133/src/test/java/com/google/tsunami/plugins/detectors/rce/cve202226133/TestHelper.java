package com.google.tsunami.plugins.detectors.rce.cve202226133;

import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.proto.*;

import java.time.Instant;

import static com.google.tsunami.common.data.NetworkEndpointUtils.forIpAndPort;

final class TestHelper {
    static final byte[] CLUSTER_NAME =
        new byte[] {0, 0, 0, 17, 98, 105, 116, 98, 117, 99, 107, 101, 116, 45, 99, 108, 117, 115, 116, 101, 114};
    static TargetInfo targetInfo() {
        return TargetInfo.newBuilder().addNetworkEndpoints(forIpAndPort("127.0.0.1", 5701)).build();
    }

    static NetworkService bitbucketClusterService() {
        return NetworkService.newBuilder()
            .setNetworkEndpoint(forIpAndPort("127.0.0.1", 5701))
            .setTransportProtocol(TransportProtocol.TCP)
            .setServiceName("unknown")
            .build();
    }

    static DetectionReport buildValidDetectionReport(
        TargetInfo targetInfo, NetworkService service, FakeUtcClock fakeUtcClock) {
        return DetectionReport.newBuilder()
            .setTargetInfo(targetInfo())
            .setNetworkService(bitbucketClusterService())
            .setDetectionTimestamp(Timestamps.fromMillis(Instant.now(fakeUtcClock).toEpochMilli()))
            .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
            .setVulnerability(
                Vulnerability.newBuilder()
                    .setMainId(
                        VulnerabilityId.newBuilder()
                            .setPublisher("TSUNAMI_COMMUNITY")
                            .setValue("CVE-2022-26133"))
                    .setSeverity(Severity.CRITICAL)
                    .setTitle("Atlassian Bitbucket DC RCE (CVE-2022-26133)")
                    .setDescription(
                        "SharedSecretClusterAuthenticator in Atlassian Bitbucket Data Center versions"
                            + " 5.14.0 and later before 7.6.14, 7.7.0 and later prior to 7.17.6,"
                            + " 7.18.0 and later prior to 7.18.4, 7.19.0 and later prior"
                            + " to 7.19.4, and 7.20.0 allow a remote, unauthenticated attacker to "
                            + "execute arbitrary code via Java deserialization."))
            .build();
    }
}
