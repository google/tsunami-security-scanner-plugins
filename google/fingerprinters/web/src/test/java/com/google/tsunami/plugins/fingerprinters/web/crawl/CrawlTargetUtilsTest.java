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

import static com.google.common.net.HttpHeaders.CONTENT_LOCATION;
import static com.google.common.net.HttpHeaders.LINK;
import static com.google.common.net.HttpHeaders.LOCATION;
import static com.google.common.truth.Truth.assertThat;
import static com.google.common.truth.extensions.proto.ProtoTruth.assertThat;

import com.google.auto.value.AutoValue;
import com.google.common.base.Splitter;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.tsunami.common.net.http.HttpHeaders;
import com.google.tsunami.common.net.http.HttpMethod;
import com.google.tsunami.proto.CrawlTarget;
import okhttp3.HttpUrl;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Tests for {@link CrawlTargetUtils}. */
@RunWith(Theories.class)
public final class CrawlTargetUtilsTest {
  private static final String BASE_URL = "https://www.google.com";

  @Test
  public void extractFromHeaders_withLocationHeader_extractsAbsoluteUrl() {
    HttpHeaders locationHeader = HttpHeaders.builder().addHeader(LOCATION, "/location").build();

    assertThat(CrawlTargetUtils.extractFromHeaders(locationHeader, HttpUrl.parse(BASE_URL)))
        .containsExactly(
            CrawlTarget.newBuilder()
                .setHttpMethod(HttpMethod.GET.toString())
                .setUrl(BASE_URL + "/location")
                .build());
  }

  @Test
  public void extractFromHeaders_withContentLocationHeader_extractsAbsoluteUrl() {
    HttpHeaders locationHeader =
        HttpHeaders.builder().addHeader(CONTENT_LOCATION, "/content-location").build();

    assertThat(CrawlTargetUtils.extractFromHeaders(locationHeader, HttpUrl.parse(BASE_URL)))
        .containsExactly(
            CrawlTarget.newBuilder()
                .setHttpMethod(HttpMethod.GET.toString())
                .setUrl(BASE_URL + "/content-location")
                .build());
  }

  @Test
  public void extractFromHeaders_withLinkHeader_extractsAbsoluteUrl() {
    HttpHeaders locationHeader =
        HttpHeaders.builder().addHeader(LINK, "</link>; rel=\"preconnect\"").build();

    assertThat(CrawlTargetUtils.extractFromHeaders(locationHeader, HttpUrl.parse(BASE_URL)))
        .containsExactly(
            CrawlTarget.newBuilder()
                .setHttpMethod(HttpMethod.GET.toString())
                .setUrl(BASE_URL + "/link")
                .build());
  }

  @Test
  public void extractFromHeaders_withMultipleHeaderValues_extractsAllAbsoluteUrls() {
    HttpHeaders headers =
        HttpHeaders.builder()
            .addHeader(LOCATION, "/location1")
            .addHeader(LOCATION, "/location2")
            .addHeader(CONTENT_LOCATION, "/content-location")
            .addHeader(LINK, "</link1>; rel=\"preconnect\", </link2>; rel=\"preconnect\"")
            .build();

    assertThat(CrawlTargetUtils.extractFromHeaders(headers, HttpUrl.parse(BASE_URL)))
        .containsExactly(
            CrawlTarget.newBuilder()
                .setHttpMethod(HttpMethod.GET.toString())
                .setUrl(BASE_URL + "/location1")
                .build(),
            CrawlTarget.newBuilder()
                .setHttpMethod(HttpMethod.GET.toString())
                .setUrl(BASE_URL + "/location2")
                .build(),
            CrawlTarget.newBuilder()
                .setHttpMethod(HttpMethod.GET.toString())
                .setUrl(BASE_URL + "/content-location")
                .build(),
            CrawlTarget.newBuilder()
                .setHttpMethod(HttpMethod.GET.toString())
                .setUrl(BASE_URL + "/link1")
                .build(),
            CrawlTarget.newBuilder()
                .setHttpMethod(HttpMethod.GET.toString())
                .setUrl(BASE_URL + "/link2")
                .build());
  }

  @Test
  public void extractFromHeaders_withInvalidLinkHeaders_ignoresAllInvalidLinks() {
    HttpHeaders headers =
        HttpHeaders.builder()
            .addHeader(LINK, "</valid-link>")
            .addHeader(LINK, "<> rel=\"preconnect\"")
            .addHeader(LINK, "< rel=\"preconnect\"")
            .addHeader(LINK, "</link rel=\"preconnect\"")
            .addHeader(LINK, "rel=\"preconnect\" <>")
            .build();

    assertThat(CrawlTargetUtils.extractFromHeaders(headers, HttpUrl.parse(BASE_URL)))
        .containsExactly(
            CrawlTarget.newBuilder()
                .setHttpMethod(HttpMethod.GET.toString())
                .setUrl(BASE_URL + "/valid-link")
                .build());
  }

  @AutoValue
  abstract static class HtmlLinkTestCase {
    abstract String htmlSnippet();
    abstract String expectedUrl();

    static HtmlLinkTestCase create(String htmlSnippet, String expectedUrl) {
      return new com.google.tsunami.plugins.fingerprinters.web.crawl
          .AutoValue_CrawlTargetUtilsTest_HtmlLinkTestCase(htmlSnippet, expectedUrl);
    }
  }

  @DataPoints("LinkAttributeCoverage")
  public static ImmutableList<HtmlLinkTestCase> linkAttributeCoverageCases() {
    return ImmutableList.of(
        HtmlLinkTestCase.create("<form action=\"/form-action\"></form>", BASE_URL + "/form-action"),
        HtmlLinkTestCase.create(
            "<applet archive=\"/applet-archive\"></applet>", BASE_URL + "/applet-archive"),
        HtmlLinkTestCase.create(
            "<body background=\"/body-background\"></body>", BASE_URL + "/body-background"),
        HtmlLinkTestCase.create(
            "<blockquote cite=\"/quote-cite\"></blockquote>", BASE_URL + "/quote-cite"),
        HtmlLinkTestCase.create(
            "<applet codebase=\"/applet-codebase\"></applet>", BASE_URL + "/applet-codebase"),
        HtmlLinkTestCase.create(
            "<object data=\"/object-data\"></object>", BASE_URL + "/object-data"),
        HtmlLinkTestCase.create("<a href=\"/a-href\"></a>", BASE_URL + "/a-href"),
        HtmlLinkTestCase.create("<img longdesc=\"/img-longdesc\">", BASE_URL + "/img-longdesc"),
        HtmlLinkTestCase.create(
            "<head profile=\"/head-profile\"></head>", BASE_URL + "/head-profile"),
        HtmlLinkTestCase.create("<img src=\"/img-src\">", BASE_URL + "/img-src"),
        HtmlLinkTestCase.create(
            "<button formaction=\"/formaction\"></button>", BASE_URL + "/formaction"),
        HtmlLinkTestCase.create(
            "<html manifest=\"/html-manifest\"></html>", BASE_URL + "/html-manifest"),
        HtmlLinkTestCase.create(
            "<video poster=\"/video-poster\"></video>", BASE_URL + "/video-poster"),
        HtmlLinkTestCase.create(
            "<iframe srcdoc=\"/iframe-srcdoc\"></iframe>", BASE_URL + "/iframe-srcdoc"),
        HtmlLinkTestCase.create("<a ping=\"/a-ping\"></a>", BASE_URL + "/a-ping"));
  }

  @Theory
  public void extractFromHtml_withHtmlSnippetOnLinkAttribute_extractsAbsoluteUrl(
      @FromDataPoints("LinkAttributeCoverage") HtmlLinkTestCase testCase) {
    String html = testCase.htmlSnippet();
    String expectedAbsoluteUrl = testCase.expectedUrl();

    assertThat(CrawlTargetUtils.extractFromHtml(html, HttpUrl.parse(BASE_URL)))
        .containsExactly(
            CrawlTarget.newBuilder().setHttpMethod("GET").setUrl(expectedAbsoluteUrl).build());
  }

  @Test
  public void
      extractFromHtml_withFormTagActionAttributePostMethod_extractsAbsoluteUrlWithPostMethod() {
    String html =
        "<form action=\"/form-action\" method=\"PosT\">\n"
            + "<input type=\"text\" id=\"id1\" name=\"text\">\n"
            + "<input type=\"radio\" id=\"id2\" name=\"radio\">\n"
            + "<input type=\"radio\" id=\"id3\" name=\"radio\">\n"
            + "<input type=\"checkbox\" id=\"id4\" name=\"checkbox1\" value=\"value1\">\n"
            + "<input type=\"checkbox\" id=\"id5\" name=\"checkbox2\" value=\"value2\">\n"
            + "<input type=\"checkbox\" id=\"id5\" name=\"checkbox2\" value=\"value2\">\n"
            + "<select name=\"select\" id=\"select\">\n"
            + "<option value=\"option1\">option1</option>\n"
            + "<option value=\"option2\">option2</option>\n"
            + "</select>\n"
            + "<input type=\"submit\" value=\"Submit\">\n"
            + "</form>";

    ImmutableSet<CrawlTarget> crawlTargets =
        CrawlTargetUtils.extractFromHtml(html, HttpUrl.parse(BASE_URL));

    assertThat(crawlTargets)
        .comparingExpectedFieldsOnly()
        .containsExactly(
            CrawlTarget.newBuilder()
                .setHttpMethod("POST")
                .setUrl(BASE_URL + "/form-action")
                .build());
    assertThat(
            Splitter.on("&")
                .split(crawlTargets.iterator().next().getHttpRequestBody().toStringUtf8()))
        .containsExactly(
            "text=test", "radio=test", "checkbox1=value1", "checkbox2=value2", "select=option1");
  }

  @Test
  public void extractFromHtml_withFormTagActionAttributeGetMethod_appendsToExistingQueryParams() {
    String html =
        "<form action=\"/form-action/?form=form1\" method=\"get\">\n"
            + "<input type=\"text\" id=\"id1\" name=\"text\">\n"
            + "<input type=\"radio\" id=\"id2\" name=\"radio\">\n"
            + "<input type=\"radio\" id=\"id3\" name=\"radio\">\n"
            + "<input type=\"checkbox\" id=\"id4\" name=\"checkbox1\" value=\"value1\">\n"
            + "<input type=\"checkbox\" id=\"id5\" name=\"checkbox2\" value=\"value2\">\n"
            + "<input type=\"checkbox\" id=\"id5\" name=\"checkbox2\" value=\"value2\">\n"
            + "<select name=\"select\" id=\"select\">\n"
            + "</select>\n"
            + "<input type=\"submit\" value=\"Submit\">\n"
            + "</form>";

    ImmutableSet<CrawlTarget> crawlTargets =
        CrawlTargetUtils.extractFromHtml(html, HttpUrl.parse(BASE_URL));

    assertThat(crawlTargets).hasSize(1);
    CrawlTarget crawlTarget = crawlTargets.iterator().next();
    assertThat(crawlTarget.getHttpMethod()).isEqualTo("GET");
    assertThat(crawlTarget.getUrl()).startsWith(BASE_URL + "/form-action/?form=form1&");
    assertThat(
            Splitter.on("&")
                .split(
                    crawlTarget
                        .getUrl()
                        .substring((BASE_URL + "/form-action/?form=form1&").length())))
        .containsExactly(
            "text=test", "radio=test", "checkbox1=value1", "checkbox2=value2", "select=test");
  }

  @Test
  public void extractFromHtml_withPathRelativeUrl_extractsAbsoluteUrl() {
    String html = "<a href=\"path/relative\"></a>";
    assertThat(CrawlTargetUtils.extractFromHtml(html, HttpUrl.parse(BASE_URL + "/existing/path/")))
        .containsExactly(
            CrawlTarget.newBuilder()
                .setHttpMethod("GET")
                .setUrl(BASE_URL + "/existing/path/path/relative")
                .build());
  }

  @Test
  public void extractFromHtml_withRootRelativeUrl_extractsAbsoluteUrl() {
    String html = "<a href=\"/root/relative\"></a>";
    assertThat(CrawlTargetUtils.extractFromHtml(html, HttpUrl.parse(BASE_URL + "/existing/path/")))
        .containsExactly(
            CrawlTarget.newBuilder()
                .setHttpMethod("GET")
                .setUrl(BASE_URL + "/root/relative")
                .build());
  }

  @Test
  public void extractFromHtml_withProtocolRelativeUrl_extractsAbsoluteUrl() {
    String html = "<a href=\"//protocol/relative\"></a>";
    assertThat(CrawlTargetUtils.extractFromHtml(html, HttpUrl.parse(BASE_URL)))
        .containsExactly(
            CrawlTarget.newBuilder()
                .setHttpMethod("GET")
                .setUrl("https://protocol/relative")
                .build());
  }

  @Test
  public void extractFromHtml_withBaseHrefAndRelativeUrl_extractsAbsoluteUrl() {
    String html = "<base href=\"http://base/path/\"><a href=\"relative/path\"></a>";
    assertThat(CrawlTargetUtils.extractFromHtml(html, HttpUrl.parse(BASE_URL)))
        .containsExactly(
            CrawlTarget.newBuilder()
                .setHttpMethod("GET")
                .setUrl("http://base/path/relative/path")
                .build());
  }

  @Test
  public void extractFromHtml_withInvalidBaseHref_ignoresInvalidBaseHref() {
    String html = "<base href=\"invalid\"><a href=\"/relative/path\"></a>";
    assertThat(CrawlTargetUtils.extractFromHtml(html, HttpUrl.parse(BASE_URL)))
        .containsExactly(
            CrawlTarget.newBuilder()
                .setHttpMethod("GET")
                .setUrl(BASE_URL + "/relative/path")
                .build());
  }

  @Test
  public void extractFromHtml_whenNoLinkAttribute_returnsEmpty() {
    String html = "<html></html>";
    assertThat(CrawlTargetUtils.extractFromHtml(html, HttpUrl.parse(BASE_URL))).isEmpty();
  }

  @Test
  public void extractFromHtml_whenLinkAttributeHasNoValue_returnsEmpty() {
    String html = "<a href></a>";
    assertThat(CrawlTargetUtils.extractFromHtml(html, HttpUrl.parse(BASE_URL))).isEmpty();
  }
}
