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

import static com.google.common.base.Strings.isNullOrEmpty;
import static java.nio.charset.StandardCharsets.ISO_8859_1;

import com.google.common.base.Ascii;
import com.google.common.base.Splitter;
import com.google.common.collect.ImmutableList;
import com.google.common.net.HostAndPort;
import com.google.common.net.InetAddresses;
import com.google.tsunami.proto.CrawlResult;
import com.google.tsunami.proto.NetworkEndpoint;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.WebServiceContext;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * Raw case-preserving parser for HTTP/2 {@code TRACE} {@code message/http} responses and endpoint
 * authority/path helpers.
 */
final class TraceEchoParser {

  private TraceEchoParser() {}

  static final class HeaderPair {
    final String name;
    final String value;

    HeaderPair(String name, String value) {
      this.name = name;
      this.value = value;
    }
  }

  /**
   * Captures the exact wire casing of echoed {@code TRACE} request headers and trailing body bytes.
   *
   * <p>Apache {@code mod_http2} canonicalizes lowercase HTTP/2 header names via {@code
   * h2_util_camel_case_header()} when populating {@code r->headers_in}, whereas non-Apache HTTP/2
   * stacks (such as Tomcat or Jetty) preserve lowercase HPACK header names.
   */
  static final class ParsedTraceEcho {
    final String requestLine;
    final ImmutableList<HeaderPair> headers;
    final byte[] body;

    ParsedTraceEcho(String requestLine, ImmutableList<HeaderPair> headers, byte[] body) {
      this.requestLine = requestLine;
      this.headers = headers;
      this.body = body.clone();
    }

    boolean hasExactCaseHeader(String exactName, String expectedValue) {
      for (HeaderPair h : headers) {
        if (h.name.equals(exactName) && h.value.equals(expectedValue)) {
          return true;
        }
      }
      return false;
    }

    boolean hasHeaderIgnoreCase(String name) {
      for (HeaderPair h : headers) {
        if (Ascii.equalsIgnoreCase(h.name, name)) {
          return true;
        }
      }
      return false;
    }
  }

  static Optional<ParsedTraceEcho> parseTraceEcho(byte[] payload) {
    String raw = new String(payload, ISO_8859_1);
    int sepIdx = raw.indexOf("\r\n\r\n");
    int sepLen = 4;
    String lineSep = "\r\n";
    if (sepIdx == -1) {
      sepIdx = raw.indexOf("\n\n");
      sepLen = 2;
      lineSep = "\n";
    }
    if (sepIdx == -1) {
      return Optional.empty();
    }

    String headSection = raw.substring(0, sepIdx);
    byte[] bodyBytes = Arrays.copyOfRange(payload, sepIdx + sepLen, payload.length);

    List<String> lines = Splitter.on(lineSep).splitToList(headSection);
    String reqLine = stripTrailingCarriageReturn(lines.get(0));
    if (reqLine.isEmpty()) {
      return Optional.empty();
    }

    ImmutableList.Builder<HeaderPair> headers = ImmutableList.builder();
    for (int i = 1; i < lines.size(); i++) {
      String line = stripTrailingCarriageReturn(lines.get(i));
      int colon = line.indexOf(':');
      if (colon <= 0) {
        return Optional.empty();
      }
      String name = line.substring(0, colon);
      String val = line.substring(colon + 1).trim();
      headers.add(new HeaderPair(name, val));
    }

    return Optional.of(new ParsedTraceEcho(reqLine, headers.build(), bodyBytes));
  }

  static boolean isMessageHttpContentType(String raw) {
    String mediaType = raw;
    int semi = mediaType.indexOf(';');
    if (semi >= 0) {
      mediaType = mediaType.substring(0, semi);
    }
    return Ascii.equalsIgnoreCase(mediaType.trim(), "message/http");
  }

  static final class EndpointTarget {
    final String dialHost;
    final String authHost;
    final int port;
    final String authority;
    final String sniHost;

    EndpointTarget(String dialHost, String authHost, int port, String authority, String sniHost) {
      this.dialHost = dialHost;
      this.authHost = authHost;
      this.port = port;
      this.authority = authority;
      this.sniHost = sniHost;
    }

    String authorityForMode(H2ProbeSession.TransportMode mode) {
      boolean isDefaultPort =
          (mode == H2ProbeSession.TransportMode.H2C && port == 80)
              || (mode == H2ProbeSession.TransportMode.H2_TLS && port == 443);
      if (isDefaultPort) {
        return HostAndPort.fromHost(authHost).toString();
      }
      return authority;
    }
  }

  static Optional<EndpointTarget> resolveEndpointTarget(NetworkEndpoint endpoint, int defaultPort) {
    int port = endpoint.getPort().getPortNumber();
    if (port <= 0) {
      port = defaultPort;
    }

    String hostname = normalizeEndpointHost(endpoint.getHostname().getName());
    String ipAddr = stripBrackets(endpoint.getIpAddress().getAddress().trim());
    if (hostname.isEmpty() && ipAddr.isEmpty()) {
      return Optional.empty();
    }

    String dialHost = ipAddr.isEmpty() ? hostname : ipAddr;
    String authHost = hostname.isEmpty() ? dialHost : hostname;

    boolean isIpLiteral = InetAddresses.isInetAddress(authHost);
    String sniHost = isIpLiteral ? "" : authHost;
    String authority = HostAndPort.fromParts(authHost, port).toString();

    return Optional.of(new EndpointTarget(dialHost, authHost, port, authority, sniHost));
  }

  private static String normalizeEndpointHost(String raw) {
    String h = stripBrackets(raw.trim());
    while (h.endsWith(".")) {
      h = h.substring(0, h.length() - 1);
    }
    return Ascii.toLowerCase(h);
  }

  static ImmutableList<String> extractCandidatePaths(NetworkService service, int maxCrawled) {
    Set<String> seen = new LinkedHashSet<>();
    seen.add("/");

    WebServiceContext wsc = service.getServiceContext().getWebServiceContext();
    String root = sanitizeRequestPath(wsc.getApplicationRoot());
    if (!root.isEmpty()) {
      seen.add(root);
    }

    int servicePort = resolvedServicePort(service);
    NetworkEndpoint ep = service.getNetworkEndpoint();
    String epHostname = normalizeEndpointHost(ep.getHostname().getName());
    String epIp = stripBrackets(ep.getIpAddress().getAddress().trim());

    int added = 0;
    for (CrawlResult cr : wsc.getCrawlResultsList()) {
      if (added >= maxCrawled) {
        break;
      }
      String rawUrl = cr.getCrawlTarget().getUrl().trim();
      if (rawUrl.isEmpty()) {
        continue;
      }
      try {
        URI uri = new URI(rawUrl);
        if (!isSameOriginCrawlUri(rawUrl, uri, epHostname, epIp, servicePort)) {
          continue;
        }
        String candidate = uri.getRawPath();
        if (isNullOrEmpty(candidate)) {
          candidate = "/";
        }
        if (!isNullOrEmpty(uri.getRawQuery())) {
          candidate = candidate + "?" + uri.getRawQuery();
        }
        String clean = sanitizeRequestPath(candidate);
        if (!clean.isEmpty() && seen.add(clean)) {
          added++;
        }
      } catch (URISyntaxException e) {
        // Ignore malformed crawled URLs.
      }
    }

    return ImmutableList.copyOf(seen);
  }

  private static int resolvedServicePort(NetworkService service) {
    int port = service.getNetworkEndpoint().getPort().getPortNumber();
    if (port > 0) {
      return port;
    }
    return Cve2026119618Detector.preferredTransports(service).get(0)
            == H2ProbeSession.TransportMode.H2_TLS
        ? 443
        : 80;
  }

  private static boolean isSameOriginCrawlUri(
      String rawUrl, URI uri, String epHostname, String epIp, int servicePort) {
    String scheme = uri.getScheme();
    if (scheme == null) {
      return uri.getRawAuthority() == null && !rawUrl.startsWith("//");
    }
    String lowerScheme = Ascii.toLowerCase(scheme);
    if (!lowerScheme.equals("http") && !lowerScheme.equals("https")) {
      return false;
    }
    String rawHost = uri.getHost();
    if (rawHost == null) {
      return false;
    }
    String urlHost = normalizeEndpointHost(rawHost);
    if (!matchesEndpointHost(urlHost, epHostname, epIp)) {
      return false;
    }
    int urlPort = uri.getPort();
    if (urlPort < 0) {
      urlPort = lowerScheme.equals("https") ? 443 : 80;
    }
    return urlPort == servicePort;
  }

  private static boolean matchesEndpointHost(String urlHost, String epHostname, String epIp) {
    if (Ascii.equalsIgnoreCase(urlHost, epHostname)) {
      return true;
    }
    if (InetAddresses.isInetAddress(urlHost) && InetAddresses.isInetAddress(epIp)) {
      return InetAddresses.forString(urlHost).equals(InetAddresses.forString(epIp));
    }
    return false;
  }

  static String sanitizeRequestPath(String raw) {
    String trimmed = raw.trim();
    if (trimmed.isEmpty()) {
      return "";
    }
    int frag = trimmed.indexOf('#');
    if (frag >= 0) {
      trimmed = trimmed.substring(0, frag);
    }
    if (trimmed.isEmpty()) {
      return "/";
    }
    for (int i = 0; i < trimmed.length(); i++) {
      char c = trimmed.charAt(i);
      if (c <= 0x20 || c >= 0x7f) {
        return "";
      }
    }
    if (!trimmed.startsWith("/")) {
      trimmed = "/" + trimmed;
    }
    return trimmed;
  }

  static String stripBrackets(String host) {
    if (host.startsWith("[") && host.endsWith("]")) {
      return host.substring(1, host.length() - 1);
    }
    return host;
  }

  private static String stripTrailingCarriageReturn(String line) {
    if (line.endsWith("\r")) {
      return line.substring(0, line.length() - 1);
    }
    return line;
  }
}
