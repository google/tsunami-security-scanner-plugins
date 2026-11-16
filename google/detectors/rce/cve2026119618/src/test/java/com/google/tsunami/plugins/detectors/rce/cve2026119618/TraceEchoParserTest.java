/*
 * Copyright 2026 Google LLC
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
package com.google.tsunami.plugins.detectors.rce.cve2026119618;

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.ISO_8859_1;

import com.google.common.collect.ImmutableList;
import com.google.tsunami.plugins.detectors.rce.cve2026119618.TraceEchoParser.EndpointTarget;
import com.google.tsunami.plugins.detectors.rce.cve2026119618.TraceEchoParser.ParsedTraceEcho;
import com.google.tsunami.proto.CrawlResult;
import com.google.tsunami.proto.CrawlTarget;
import com.google.tsunami.proto.Hostname;
import com.google.tsunami.proto.IpAddress;
import com.google.tsunami.proto.NetworkEndpoint;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.Port;
import com.google.tsunami.proto.ServiceContext;
import com.google.tsunami.proto.TransportProtocol;
import com.google.tsunami.proto.WebServiceContext;
import java.util.Optional;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link TraceEchoParser}. */
@RunWith(JUnit4.class)
public final class TraceEchoParserTest {

  @Test
  public void parseTraceEcho_withCrlfAndBody_preservesExactHeaderCaseAndBody() {
    byte[] payload =
        String.join(
                "\r\n",
                "TRACE / HTTP/2.0",
                "Host: 127.0.0.1:8080",
                "Content-Type: text/plain",
                "x-lowercase-only: val",
                "X-Tsunami-Probe: deadbeef",
                "",
                "x")
            .getBytes(ISO_8859_1);

    Optional<ParsedTraceEcho> parsed = TraceEchoParser.parseTraceEcho(payload);

    assertThat(parsed).isPresent();
    ParsedTraceEcho echo = parsed.get();
    assertThat(echo.requestLine).isEqualTo("TRACE / HTTP/2.0");
    assertThat(echo.body).isEqualTo("x".getBytes(ISO_8859_1));
    assertThat(echo.hasExactCaseHeader("Host", "127.0.0.1:8080")).isTrue();
    assertThat(echo.hasExactCaseHeader("host", "127.0.0.1:8080")).isFalse();
    assertThat(echo.hasExactCaseHeader("X-Tsunami-Probe", "deadbeef")).isTrue();
    assertThat(echo.hasExactCaseHeader("x-tsunami-probe", "deadbeef")).isFalse();
    assertThat(echo.hasExactCaseHeader("X-Lowercase-Only", "val")).isFalse();
    assertThat(echo.hasHeaderIgnoreCase("X-LOWERCASE-ONLY")).isTrue();
    assertThat(echo.hasHeaderIgnoreCase("Content-Length")).isFalse();
  }

  @Test
  public void parseTraceEcho_withLfTerminators_parsesRequestAndHeaders() {
    byte[] payload = "TRACE /status HTTP/2.0\nHost: 127.0.0.1:80\n\n".getBytes(ISO_8859_1);

    Optional<ParsedTraceEcho> parsed = TraceEchoParser.parseTraceEcho(payload);

    assertThat(parsed).isPresent();
    assertThat(parsed.get().requestLine).isEqualTo("TRACE /status HTTP/2.0");
    assertThat(parsed.get().hasExactCaseHeader("Host", "127.0.0.1:80")).isTrue();
    assertThat(parsed.get().body).isEmpty();
  }

  @Test
  public void parseTraceEcho_withMalformedInputs_returnsEmpty() {
    assertThat(
            TraceEchoParser.parseTraceEcho("TRACE / HTTP/2.0\r\nHost: x\r\n".getBytes(ISO_8859_1)))
        .isEmpty();
    assertThat(TraceEchoParser.parseTraceEcho("\r\nHost: x\r\n\r\n".getBytes(ISO_8859_1)))
        .isEmpty();
    assertThat(
            TraceEchoParser.parseTraceEcho(
                "TRACE / HTTP/2.0\r\nNoColonHeader\r\n\r\n".getBytes(ISO_8859_1)))
        .isEmpty();
    assertThat(
            TraceEchoParser.parseTraceEcho(
                "TRACE / HTTP/2.0\r\n:emptyHeaderName\r\n\r\n".getBytes(ISO_8859_1)))
        .isEmpty();
  }

  @Test
  public void isMessageHttpContentType_stripsParametersCaseInsensitively() {
    assertThat(TraceEchoParser.isMessageHttpContentType("message/http")).isTrue();
    assertThat(TraceEchoParser.isMessageHttpContentType("message/http; charset=ISO-8859-1"))
        .isTrue();
    assertThat(TraceEchoParser.isMessageHttpContentType("MESSAGE/HTTP ; boundary=xyz")).isTrue();
    assertThat(TraceEchoParser.isMessageHttpContentType("text/plain")).isFalse();
    assertThat(TraceEchoParser.isMessageHttpContentType("")).isFalse();
  }

  @Test
  public void resolveEndpointTarget_handlesIpv4Ipv6AndDnsSniRules() {
    assertThat(TraceEchoParser.resolveEndpointTarget(NetworkEndpoint.getDefaultInstance(), 80))
        .isEmpty();

    NetworkEndpoint dotOnlyEp =
        NetworkEndpoint.newBuilder().setHostname(Hostname.newBuilder().setName("...")).build();
    assertThat(TraceEchoParser.resolveEndpointTarget(dotOnlyEp, 80)).isEmpty();

    NetworkEndpoint ipv4Ep =
        NetworkEndpoint.newBuilder()
            .setIpAddress(IpAddress.newBuilder().setAddress("127.0.0.1"))
            .build();
    EndpointTarget ipv4Target = TraceEchoParser.resolveEndpointTarget(ipv4Ep, 443).orElseThrow();
    assertThat(ipv4Target.dialHost).isEqualTo("127.0.0.1");
    assertThat(ipv4Target.port).isEqualTo(443);
    assertThat(ipv4Target.authority).isEqualTo("127.0.0.1:443");
    assertThat(ipv4Target.authorityForMode(H2ProbeSession.TransportMode.H2_TLS))
        .isEqualTo("127.0.0.1");
    assertThat(ipv4Target.authorityForMode(H2ProbeSession.TransportMode.H2C))
        .isEqualTo("127.0.0.1:443");
    assertThat(ipv4Target.sniHost).isEmpty();

    NetworkEndpoint ipv6Ep =
        NetworkEndpoint.newBuilder()
            .setIpAddress(IpAddress.newBuilder().setAddress("[2001:db8::1]"))
            .setPort(Port.newBuilder().setPortNumber(80))
            .build();
    EndpointTarget ipv6Target = TraceEchoParser.resolveEndpointTarget(ipv6Ep, 443).orElseThrow();
    assertThat(ipv6Target.dialHost).isEqualTo("2001:db8::1");
    assertThat(ipv6Target.port).isEqualTo(80);
    assertThat(ipv6Target.authority).isEqualTo("[2001:db8::1]:80");
    assertThat(ipv6Target.authorityForMode(H2ProbeSession.TransportMode.H2C))
        .isEqualTo("[2001:db8::1]");
    assertThat(ipv6Target.authorityForMode(H2ProbeSession.TransportMode.H2_TLS))
        .isEqualTo("[2001:db8::1]:80");
    assertThat(ipv6Target.sniHost).isEmpty();

    NetworkEndpoint dnsWithIpEp =
        NetworkEndpoint.newBuilder()
            .setHostname(Hostname.newBuilder().setName("APACHE.Example.Test."))
            .setIpAddress(IpAddress.newBuilder().setAddress("127.0.0.1"))
            .setPort(Port.newBuilder().setPortNumber(8443))
            .build();
    EndpointTarget dnsTarget =
        TraceEchoParser.resolveEndpointTarget(dnsWithIpEp, 443).orElseThrow();
    assertThat(dnsTarget.dialHost).isEqualTo("127.0.0.1");
    assertThat(dnsTarget.authority).isEqualTo("apache.example.test:8443");
    assertThat(dnsTarget.authorityForMode(H2ProbeSession.TransportMode.H2_TLS))
        .isEqualTo("apache.example.test:8443");
    assertThat(dnsTarget.sniHost).isEqualTo("apache.example.test");
  }

  @Test
  public void extractCandidatePaths_enforcesSameOriginSanitizesAndCapsFallbacks() {
    WebServiceContext webContext =
        WebServiceContext.newBuilder()
            .setApplicationRoot("app#ignore")
            // Off-origin external domain (including same port 8080) -> must be skipped
            .addCrawlResults(crawlResult("https://cdn.external.example/assets/app.js"))
            .addCrawlResults(crawlResult("http://cdn.external.example:8080/assets/same-port.js"))
            // Off-origin IP address on same port 8080 -> must be skipped
            .addCrawlResults(crawlResult("http://192.0.2.99:8080/wrong-ip"))
            // Protocol-relative off-origin -> must be skipped
            .addCrawlResults(crawlResult("//evil.example/phish"))
            // Cross-port -> must be skipped
            .addCrawlResults(crawlResult("http://apache.example.test:9999/wrong-port"))
            // Non-HTTP scheme (including matching host and port) -> must be skipped
            .addCrawlResults(crawlResult("javascript:alert(1)"))
            .addCrawlResults(crawlResult("ftp://apache.example.test:8080/pub"))
            // Control/space bytes -> must be rejected
            .addCrawlResults(crawlResult("http://apache.example.test:8080/bad path"))
            // Missing host authority -> must be skipped
            .addCrawlResults(crawlResult("http://:8080/missing-host"))
            // Same-origin #1 (hostname with trailing dot + port, fragment stripped)
            .addCrawlResults(crawlResult("http://apache.example.test.:8080/portal/login?x=1#top"))
            // Same-origin #2 (endpoint IP + port)
            .addCrawlResults(crawlResult("http://127.0.0.1:8080/api/v1"))
            // Same-origin #3 (beyond maxCrawled = 2)
            .addCrawlResults(crawlResult("http://apache.example.test:8080/third"))
            .build();

    NetworkService service =
        NetworkService.newBuilder()
            .setTransportProtocol(TransportProtocol.TCP)
            .setServiceName("http")
            .setNetworkEndpoint(
                NetworkEndpoint.newBuilder()
                    .setHostname(Hostname.newBuilder().setName("apache.example.test"))
                    .setIpAddress(IpAddress.newBuilder().setAddress("127.0.0.1"))
                    .setPort(Port.newBuilder().setPortNumber(8080)))
            .setServiceContext(ServiceContext.newBuilder().setWebServiceContext(webContext))
            .build();

    ImmutableList<String> paths = TraceEchoParser.extractCandidatePaths(service, 2);

    assertThat(paths).containsExactly("/", "/app", "/portal/login?x=1", "/api/v1").inOrder();

    // Also verify relative paths, fragment-only URLs, malformed URIs, and canonical IPv6 matching
    // on default HTTPS port 443.
    WebServiceContext httpsIpv6Ctx =
        WebServiceContext.newBuilder()
            .addCrawlResults(crawlResult(""))
            .addCrawlResults(crawlResult("http://[::1]:badport/x"))
            .addCrawlResults(crawlResult("ftp://[2001:db8::1]/x"))
            .addCrawlResults(crawlResult("#only-fragment"))
            .addCrawlResults(crawlResult("relative/endpoint#frag"))
            .addCrawlResults(crawlResult("https://[2001:0db8:0:0:0:0:0:1]/v2"))
            .build();
    NetworkService httpsIpv6Svc =
        NetworkService.newBuilder()
            .setTransportProtocol(TransportProtocol.TCP)
            .setServiceName("https")
            .setNetworkEndpoint(
                NetworkEndpoint.newBuilder()
                    .setIpAddress(IpAddress.newBuilder().setAddress("2001:db8::1")))
            .setServiceContext(ServiceContext.newBuilder().setWebServiceContext(httpsIpv6Ctx))
            .build();
    assertThat(TraceEchoParser.extractCandidatePaths(httpsIpv6Svc, 3))
        .containsExactly("/", "/relative/endpoint", "/v2")
        .inOrder();

    // Verify IP-literal crawled URL, explicit :0 port, and default HTTP port 80 resolution on a
    // hostname-only service (empty epIp, port 0).
    NetworkService hostnameOnlySvc =
        NetworkService.newBuilder()
            .setTransportProtocol(TransportProtocol.TCP)
            .setServiceName("http")
            .setNetworkEndpoint(
                NetworkEndpoint.newBuilder()
                    .setHostname(Hostname.newBuilder().setName("apache.example.test")))
            .setServiceContext(
                ServiceContext.newBuilder()
                    .setWebServiceContext(
                        WebServiceContext.newBuilder()
                            .addCrawlResults(crawlResult("http://192.0.2.99/ip-on-host-only"))
                            .addCrawlResults(crawlResult("http://apache.example.test:0/zero-port"))
                            .addCrawlResults(crawlResult("https://apache.example.test/wrong-443"))
                            .addCrawlResults(crawlResult("http://apache.example.test/default-80"))))
            .build();
    assertThat(TraceEchoParser.extractCandidatePaths(hostnameOnlySvc, 3))
        .containsExactly("/", "/default-80")
        .inOrder();
    assertThat(TraceEchoParser.sanitizeRequestPath("   ")).isEmpty();
    assertThat(TraceEchoParser.sanitizeRequestPath("#frag")).isEqualTo("/");
    assertThat(TraceEchoParser.sanitizeRequestPath("\u007fbad")).isEmpty();
    assertThat(TraceEchoParser.stripBrackets("[::1]")).isEqualTo("::1");
    assertThat(TraceEchoParser.stripBrackets("[unclosed")).isEqualTo("[unclosed");
    assertThat(TraceEchoParser.stripBrackets("unopened]")).isEqualTo("unopened]");
  }

  private static CrawlResult crawlResult(String url) {
    return CrawlResult.newBuilder().setCrawlTarget(CrawlTarget.newBuilder().setUrl(url)).build();
  }
}
