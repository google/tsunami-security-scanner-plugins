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
package com.google.tsunami.plugins.fingerprinters.web.crawl;

import static com.google.common.base.Strings.isNullOrEmpty;
import static com.google.common.collect.ImmutableSet.toImmutableSet;
import static com.google.common.net.HttpHeaders.CONTENT_LOCATION;
import static com.google.common.net.HttpHeaders.LINK;
import static com.google.common.net.HttpHeaders.LOCATION;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.stream.Collectors.joining;

import com.google.common.base.Ascii;
import com.google.common.collect.ImmutableSet;
import com.google.common.flogger.GoogleLogger;
import com.google.protobuf.ByteString;
import com.google.tsunami.common.net.http.HttpHeaders;
import com.google.tsunami.common.net.http.HttpMethod;
import com.google.tsunami.proto.CrawlTarget;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import okhttp3.HttpUrl;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.nodes.FormElement;

/** Static utility methods pertaining to {@link CrawlTarget} proto buffer. */
public final class CrawlTargetUtils {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  private static final ImmutableSet<String> LINK_ATTRIBUTES =
      ImmutableSet.of(
          // HTML 4 link attributes.
          "action",
          "archive",
          "background",
          "cite",
          "codebase",
          "data",
          "href",
          "longdesc",
          "profile",
          "src",
          // HTML 5 link attributes.
          "formaction",
          "manifest",
          "poster",
          "srcdoc",
          "ping");
  // URI in LINK header must be present between characters < and >
  // (https://tools.ietf.org/html/rfc5988#section-5).
  private static final Pattern LINK_URL_PATTERN = Pattern.compile("<(?<url>[^>]+)>");

  private CrawlTargetUtils() {}

  public static ImmutableSet<CrawlTarget> extractFromHeaders(
      HttpHeaders httpHeaders, HttpUrl baseUrl) {
    return httpHeaders.names().stream()
        .filter(CrawlTargetUtils::isRedirectHeader)
        .flatMap(
            headerName ->
                getUrlsFromHeader(headerName, httpHeaders.getAll(headerName), baseUrl).stream())
        .map(
            url ->
                CrawlTarget.newBuilder()
                    .setUrl(url.toString())
                    .setHttpMethod(HttpMethod.GET.toString())
                    .build())
        .collect(toImmutableSet());
  }

  private static boolean isRedirectHeader(String headerName) {
    return Ascii.equalsIgnoreCase(headerName, LOCATION)
        || Ascii.equalsIgnoreCase(headerName, CONTENT_LOCATION)
        || Ascii.equalsIgnoreCase(headerName, LINK);
  }

  private static ImmutableSet<HttpUrl> getUrlsFromHeader(
      String headerName, Iterable<String> headerValues, HttpUrl baseUrl) {
    ImmutableSet.Builder<HttpUrl> urlsBuilder = ImmutableSet.builder();

    if (Ascii.equalsIgnoreCase(headerName, LOCATION)
        || Ascii.equalsIgnoreCase(headerName, CONTENT_LOCATION)) {
      for (String headerValue : headerValues) {
        Optional.ofNullable(baseUrl.resolve(headerValue)).ifPresent(urlsBuilder::add);
      }
    }

    if (Ascii.equalsIgnoreCase(headerName, LINK)) {
      for (String headerValue : headerValues) {
        Matcher linkUrlMatcher = LINK_URL_PATTERN.matcher(headerValue);
        while (linkUrlMatcher.find()) {
          Optional.ofNullable(linkUrlMatcher.group("url"))
              .flatMap(linkUrl -> Optional.ofNullable(baseUrl.resolve(linkUrl)))
              .ifPresent(urlsBuilder::add);
        }
      }
    }

    return urlsBuilder.build();
  }

  /** Extracts all links from an HTML page and wraps them into {@link CrawlTarget} messages. */
  public static ImmutableSet<CrawlTarget> extractFromHtml(String document, HttpUrl baseUrl) {
    return extractFromHtml(Jsoup.parse(document), baseUrl);
  }

  /** Extracts all links from an HTML page and wraps them into {@link CrawlTarget} messages. */
  public static ImmutableSet<CrawlTarget> extractFromHtml(Document document, HttpUrl baseUrl) {
    HttpUrl effectiveBaseUrl = effectiveHtmlBaseUrl(document, baseUrl);
    ImmutableSet.Builder<CrawlTarget> crawlTargetsBuilder = ImmutableSet.builder();

    for (String linkAttr : LINK_ATTRIBUTES) {
      // Ignore base tags that are handled separately.
      for (Element matchingElement : document.select(String.format("[%s]:not(base)", linkAttr))) {
        // Ignore empty links from the HTML document.
        String linkAttrValue = matchingElement.attr(linkAttr);
        if (isNullOrEmpty(linkAttrValue)) {
          continue;
        }

        Optional.ofNullable(effectiveBaseUrl.resolve(linkAttrValue))
            .ifPresent(
                httpUrl -> {
                  HttpMethod method = getHttpMethodForLink(matchingElement);
                  if (!(matchingElement instanceof FormElement)) {
                    crawlTargetsBuilder.add(
                        CrawlTarget.newBuilder()
                            .setHttpMethod(method.toString())
                            .setUrl(httpUrl.toString())
                            .build());
                    return;
                  }

                  Map<String, String> parameters = getFormParameters((FormElement) matchingElement);
                  switch (method) {
                    case GET:
                      // Append form data into get url queries.
                      HttpUrl.Builder newUrlBuilder = httpUrl.newBuilder();
                      parameters.forEach(newUrlBuilder::addQueryParameter);
                      crawlTargetsBuilder.add(
                          CrawlTarget.newBuilder()
                              .setHttpMethod(method.toString())
                              .setUrl(newUrlBuilder.build().toString())
                              .build());
                      break;
                    case POST:
                      // Set form data as POST body.
                      String formData =
                          parameters.entrySet().stream()
                              .map(
                                  entry ->
                                      urlEncode(entry.getKey()) + "=" + urlEncode(entry.getValue()))
                              .collect(joining("&"));
                      crawlTargetsBuilder.add(
                          CrawlTarget.newBuilder()
                              .setHttpMethod(method.toString())
                              .setUrl(httpUrl.toString())
                              .setHttpRequestBody(ByteString.copyFrom(formData, UTF_8))
                              .build());
                      break;
                    default:
                      logger.atWarning().log(
                          "Unsupported form method '%s'. Forms can only have GET and POST"
                              + " methods.",
                          method);
                  }
                });
      }
    }

    return crawlTargetsBuilder.build();
  }

  private static Map<String, String> getFormParameters(FormElement form) {
    Map<String, String> parameters = new HashMap<>();
    for (Element element : form.elements()) {
      if (!element.tag().isFormSubmittable()) {
        continue;
      }

      String name = element.attr("name");
      if (name.length() == 0 || parameters.containsKey(name)) {
        continue;
      }

      if (Ascii.equalsIgnoreCase(element.tagName(), "select")) {
        // For a select element, set its value to the first available option, or a predefined value
        // if no options found.
        Element option = element.select("option").first();
        parameters.put(name, option == null || isNullOrEmpty(option.val()) ? "test" : option.val());
      } else {
        // For other input types and text areas, set their values from the elements
        // themselves, or a predefined value if there is no value available.
        String value = element.val();
        parameters.put(name, isNullOrEmpty(value) ? "test" : value);
      }
    }
    return parameters;
  }

  private static HttpUrl effectiveHtmlBaseUrl(Document document, HttpUrl fallbackUrl) {
    Optional<HttpUrl> baseHref =
        Optional.ofNullable(document.select("base[href]").first())
            .flatMap(element -> Optional.ofNullable(HttpUrl.parse(element.attr("href"))));

    if (baseHref.isPresent() && !isNullOrEmpty(baseHref.get().host())) {
      return baseHref.get();
    }

    return fallbackUrl;
  }

  private static HttpMethod getHttpMethodForLink(Element element) {
    if (element instanceof FormElement
        && Ascii.equalsIgnoreCase(element.attr("method"), HttpMethod.POST.toString())) {
      return HttpMethod.POST;
    } else {
      return HttpMethod.GET;
    }
  }

  private static String urlEncode(String value) {
    try {
      return URLEncoder.encode(value, UTF_8.toString());
    } catch (UnsupportedEncodingException e) {
      throw new AssertionError("Should never happen. Unsupported encoding.", e);
    }
  }
}
