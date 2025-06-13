package com.google.tsunami.plugins.detectors.bitbucket;

import static com.google.common.truth.extensions.proto.ProtoTruth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostnameAndPort;

import com.google.common.collect.ImmutableList;
import com.google.inject.Guice;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.common.net.http.HttpStatus;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.common.time.testing.FakeUtcClockModule;
import com.google.tsunami.plugin.payload.testing.FakePayloadGeneratorModule;
import com.google.tsunami.plugin.payload.testing.PayloadTestHelper;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.Software;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.TransportProtocol;
import java.io.IOException;
import java.time.Instant;
import javax.inject.Inject;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class Cve202236804DetectorWithCallbackServerTest {

  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2022-09-15T00:00:00.00Z"));

  @Inject private Cve202236804VulnDetector detector;
  private MockWebServer mockWebServer;
  private MockWebServer mockCallbackServer;
  private NetworkService service;

  @Before
  public void setUp() throws IOException {
    mockWebServer = new MockWebServer();
    mockCallbackServer = new MockWebServer();
    mockCallbackServer.start();
    mockWebServer.start();
    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock),
            new HttpClientModule.Builder().build(),
            FakePayloadGeneratorModule.builder().setCallbackServer(mockCallbackServer).build(),
            new Cve202236804DetectorBootstrapModule())
        .injectMembers(this);

    service =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .setTransportProtocol(TransportProtocol.TCP)
            .setSoftware(Software.newBuilder().setName("bitbucket"))
            .setServiceName("http")
            .build();
  }

  @After
  public void tearDown() throws IOException {
    mockWebServer.shutdown();
    mockCallbackServer.shutdown();
  }

  @Test
  public void detect_whenVulnerable_returnsVulnerability() throws IOException {
    mockWebServer.enqueue(
        new MockResponse()
            .setResponseCode(HttpStatus.OK.code())
            .setBody(
                "HTTP/1.1 200 \n"
                    + "X-AREQUESTID: @5BAAJ5x535x416x0\n"
                    + "x-xss-protection: 1; mode=block\n"
                    + "x-frame-options: SAMEORIGIN\n"
                    + "x-content-type-options: nosniff\n"
                    + "Pragma: no-cache\n"
                    + "Expires: Thu, 01 Jan 1970 00:00:00 GMT\n"
                    + "Cache-Control: no-cache\n"
                    + "Cache-Control: no-store\n"
                    + "vary: accept-encoding\n"
                    + "Content-Type: text/html;charset=UTF-8\n"
                    + "Content-Language: en-CA\n"
                    + "Date: Wed, 14 Sep 2022 08:55:59 GMT\n"
                    + "Connection: close\n"
                    + "Content-Length: 10741\n"
                    + "\n"
                    + "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta"
                    + " http-equiv=\"X-UA-Compatible\" content=\"IE=edge\"><title>Public"
                    + " Repositories - Bitbucket</title><script>\n"
                    + "window.WRM=window.WRM||{};window.WRM._unparsedData=window.WRM._unparsedData||{};window.WRM._unparsedErrors=window.WRM._unparsedErrors||{};\n"
                    + "WRM._unparsedData[\"com.atlassian.bitbucket.server.bitbucket-webpack-INTERNAL:user-keyboard-shortcuts-enabled.data\"]=\"true\";\n"
                    + "WRM._unparsedData[\"com.atlassian.analytics.analytics-client:programmatic-analytics-init.programmatic-analytics-data-provider\"]=\"false\";\n"
                    + "WRM._unparsedData[\"com.atlassian.plugins.atlassian-plugins-webresource-plugin:context-path.context-path\"]=\"\\u0022\\u0022\";\n"
                    + "WRM._unparsedData[\"com.atlassian.plugins.atlassian-clientside-extensions-runtime:runtime.atlassianDevMode\"]=\"false\";\n"
                    + "WRM._unparsedData[\"com.atlassian.bitbucket.server.bitbucket-webpack-INTERNAL:date-format-preference.data\"]=\"\\u0022\\u0022\";\n"
                    + "WRM._unparsedData[\"com.atlassian.analytics.analytics-client:policy-update-init.policy-update-data-provider\"]=\"false\";\n"
                    + "WRM._unparsedData[\"com.atlassian.bitbucket.server.feature-wrm-data:user.time.zone.onboarding.data\"]=\"true\";\n"
                    + "if(window.WRM._dataArrived)window.WRM._dataArrived();</script>\n"
                    + "<link rel=\"stylesheet\""
                    + " href=\"/s/ced4e1b2f2ea3ac16453e3c432f2ce7a-CDN/-1548311545/e36cb0c/n1cn5w/3475ec2cd07a90fee34024045fdae7ea/_/download/contextbatch/css/_super/batch.css\""
                    + " data-wrm-key=\"_super\" data-wrm-batch-type=\"context\" media=\"all\">\n"
                    + "<link rel=\"stylesheet\""
                    + " href=\"/s/60a07222120d8dea236faee8a0fe7093-CDN/-1548311545/e36cb0c"
                    + "/n1cn5w/29c1673071be49f0b2fd1a124c22b06c/_/download/contextbatch/css/bitbucket.page"
                    + ".globalRepositoryList,bitbucket.layout.entity,bitbucket.layout.base,atl.general,-_super/batch.css\""
                    + " data-wrm-key=\"bitbucket.page.globalRepositoryList,bitbucket.layout.entity,bitbucket.layout.base,atl.general,-_super\""
                    + " data-wrm-batch-type=\"context\" media=\"all\">\n"
                    + "<script"
                    + " src=\"/s/c158a64817e06d6a1aec491b7605d822-CDN/-1548311545/e36cb0c/n1cn5w"
                    + "/3475ec2cd07a90fee34024045fdae7ea/_/download/contextbatch/js/_super/batch.js?locale=en-US\""
                    + " data-wrm-key=\"_super\" data-wrm-batch-type=\"context\""
                    + " data-initially-rendered></script>\n"
                    + "<script"
                    + " src=\"/s/2397285fbfbe68ae8ba72368530c8853-CDN/-1548311545/e36cb0c/n1cn5w"
                    + "/29c1673071be49f0b2fd1a124c22b06c/_/download/contextbatch/js/bitbucket.page"
                    + ".globalRepositoryList,bitbucket.layout.entity,bitbucket.layout.base,atl.general,-_super/batch.js?locale=en-US\""
                    + " data-wrm-key=\"bitbucket.page.globalRepositoryList,bitbucket.layout.entity,bitbucket.layout.base,atl.general,-_super\""
                    + " data-wrm-batch-type=\"context\" data-initially-rendered></script>\n"
                    + "<meta name=\"application-name\" content=\"Bitbucket\"><link rel=\"shortcut"
                    + " icon\" type=\"image/x-icon\""
                    + " href=\"/s/-1548311545/e36cb0c/n1cn5w/1.0/_/download/resources/com.atlassian.bitbucket.server.bitbucket-webpack-INTERNAL:favicon/favicon.ico\""
                    + " /><link rel=\"search\""
                    + " href=\"http://10.2.0.51:37990/plugins/servlet/opensearch-descriptor\""
                    + " type=\"application/opensearchdescription+xml\" title=\"Bitbucket code"
                    + " search\"/></head><body class=\" bitbucket-theme\"><ul"
                    + " id=\"assistive-skip-links\" class=\"assistive\"><li><a"
                    + " href=\"#content\">Skip to content</a></li></ul><div id=\"page\"><!-- start"
                    + " #header --><header id=\"header\" role=\"banner\"><section"
                    + " class=\"notifications\"></section><nav class=\"aui-header"
                    + " aui-dropdown2-trigger-group\" aria-label=\"site\"><div"
                    + " class=\"aui-header-inner\"><div class=\"aui-header-before\"></div><div"
                    + " class=\"aui-header-primary\"><span id=\"logo\" class=\"aui-header-logo"
                    + " bitbucket-header-logo\"><a href=\"http://10.2.0.51:37990\"><img "
                    + "src=\"/s/-1548311545/e36cb0c/n1cn5w/1.0/_/download/resources/com.atlassian.bitbucket.server.bitbucket-webpack-INTERNAL:bitbucket-logo/images/logo/bitbucket.svg\""
                    + " alt=\"Bitbucket\"/></a></span><ul class=\"aui-nav\"><li class=\""
                    + " projects-link\"><a href=\"/projects\"class=\"projects-link\""
                    + " data-web-item-key=\"com.atlassian.bitbucket.server.bitbucket-server-web-fragments:projects-menu\">Projects</a></li><li"
                    + " class=\" public-repos-link\"><a href=\"/repos\"class=\"public-repos-link\""
                    + " data-web-item-key=\"com"
                    + ".atlassian.bitbucket.server.bitbucket-server-web-fragments:public-repositories-link\">Repositories</a></li></ul></div><div"
                    + " class=\"aui-header-secondary\"><ul class=\"aui-nav\"><li><div"
                    + " id=\"quick-search-loader\"></div><script>jQuery(document).ready(function ()"
                    + " {require(['bitbucket-plugin-search/internal/component/quick-search/quick-search-loader'],"
                    + " function (loader) {loader.onReady('#quick-search-loader');}) ;})"
                    + " ;</script></li><li class=\" help-link\"title=\"Help\"><a class=\""
                    + " aui-dropdown2-trigger aui-dropdown2-trigger-arrowless\""
                    + " aria-controls=\"com.atlassian.bitbucket.server.bitbucket-server-web-fragments-help-menu\""
                    + " aria-haspopup=\"true\" role=\"button\" tabindex=\"0\""
                    + " data-aui-trigger><span class=\"aui-icon aui-icon-small aui-icon-small"
                    + " aui-iconfont-question-circle\">Help</span></a><div"
                    + " id=\"com.atlassian.bitbucket.server.bitbucket-server-web-fragments-help-menu\""
                    + " class=\"aui-dropdown2 aui-style-default\" role=\"menu\" hidden"
                    + " data-aui-dom-container=\"body\"><div class=\"aui-dropdown2-section"
                    + " help-items-section\"><ul class=\"aui-list-truncate\""
                    + " role=\"presentation\"><li role=\"presentation\"><a"
                    + " href=\"https://docs.atlassian"
                    + ".com/bitbucketserver/docs-083/Bitbucket+Data+Center+and+Server+documentation?utm_campaign=in-app-help&amp;amp;utm_medium=in-app-help&amp;amp;utm_source=stash\""
                    + " title=\"Go to the online documentation for Bitbucket\""
                    + " data-web-item-key=\"com.atlassian.bitbucket.server.bitbucket-server-web-fragments:general-help\">Online"
                    + " help</a></li><li role=\"presentation\"><a"
                    + " href=\"https://www.atlassian.com/git?utm_campaign=learn-git&amp;utm_medium=in-app-help&amp;utm_source=stash\""
                    + " title=\"Learn about Git commands &amp; workflows\""
                    + " data-web-item-key=\"com.atlassian.bitbucket.server.bitbucket-server-web-fragments:learn-git\">Learn"
                    + " Git</a></li><li role=\"presentation\"><a"
                    + " href=\"/getting-started\"class=\"getting-started-page-link\""
                    + " title=\"Overview of Bitbucket features\""
                    + " data-web-item-key=\"com.atlassian.bitbucket.server.bitbucket-server-web-fragments:getting-started-page-help-link\">Welcome"
                    + " to Bitbucket</a></li><li role=\"presentation\"><a"
                    + " href=\"/#\"class=\"keyboard-shortcut-link\" title=\"Discover keyboard"
                    + " shortcuts in Bitbucket\""
                    + " data-web-item-key=\"com.atlassian.bitbucket.server.bitbucket-server-web-fragments:keyboard-shortcuts-help-link\">Keyboard"
                    + " shortcuts</a></li><li role=\"presentation\"><a href=\"https://go.atlassian"
                    + ".com/bitbucket-server-whats-new?utm_campaign=in-app-help&amp;utm_medium=in-app-help&amp;utm_source=stash\""
                    + " title=\"Learn about what&#39;s new in Bitbucket\" "
                    + "data-web-item-key=\"com.atlassian.bitbucket.server.bitbucket-server-web-fragments:whats-new-link\">What&#39;s"
                    + " new</a></li><li role=\"presentation\"><a href=\"https://go.atlassian"
                    + ".com/bitbucket-server-community?utm_campaign=in-app-help&amp;utm_medium=in-app-help&amp;utm_source=stash\""
                    + " title=\"Explore the Atlassian community\" data-web-item-key=\"com"
                    + ".atlassian.bitbucket.server.bitbucket-server-web-fragments:community-link\">Community</a></li><li"
                    + " role=\"presentation\"><a href=\"/about\" title=\"About Bitbucket\" "
                    + "data-web-item-key=\"com.atlassian.bitbucket.server.bitbucket-server-web-fragments:about\">About</a></li></ul></div></div></li><li"
                    + " class=\" alerts-menu\"title=\"View system alerts\"><a href=\"#alerts\""
                    + " id=\"alerts-trigger\"class=\"alerts-menu\" title=\"View system alerts\" "
                    + "data-web-item-key=\"com.atlassian.bitbucket.server.bitbucket-server-web-fragments:global-alerts-menu-item\">Alerts</a></li><li"
                    + " class=\"user-dropdown\"><a id=\"login-link\" href=\"/login\">Log"
                    + " In</a></li></ul></div></div> <!-- End .aui-header-inner --></nav> <!-- End"
                    + " .aui-header --></header><!-- End #header --><!-- Start #content --><section"
                    + " id=\"content\" role=\"main\" tabindex=\"-1\" data-timezone=\"0\" ><header"
                    + " class=\"aui-page-header\"><section class=\"notifications\"></section><div"
                    + " class=\"aui-page-header-inner\"><div class=\"aui-page-header-main"
                    + " entity-item\"><h1><span class=\"entity-name\">Public"
                    + " Repositories</span></h1></div><div"
                    + " class=\"aui-page-header-actions\"></div></div></header><div"
                    + " id=\"aui-page-panel-content-body\" class=\"aui-page-panel content-body\" "
                    + " tabindex=\"-1\"><div class=\"aui-page-panel-inner\"><main role=\"main\""
                    + " id=\"main\" class=\"aui-page-panel-content\" ><div"
                    + " id='repository-container'></div></main></div></div></section><!-- End"
                    + " #content --><!-- Start #footer --><footer id=\"footer\""
                    + " role=\"contentinfo\"><section class=\"notifications\"></section><section"
                    + " class=\"footer-body\"><ul><li data-key=\"footer.license.free.eval\">Git"
                    + " repository management powered by a free <a"
                    + " href=\"https://www.atlassian.com/software/bitbucket/\">Atlassian"
                    + " Bitbucket</a> evaluation license</li></ul><ul><li>Atlassian Bitbucket <span"
                    + " title=\"e36cb0c5e3aab578efcf39083c1ec9adb7326c2e\" id=\"product-version\""
                    + " data-commitid=\"e36cb0c5e3aab578efcf39083c1ec9adb7326c2e\""
                    + " data-system-build-number=\"e36cb0c\"> v8.3.0</span></li><li"
                    + " data-key=\"footer.links.documentation\"><a href=\"https://docs.atlassian"
                    + ".com/bitbucketserver/docs-083/Bitbucket+Data+Center+and+Server+documentation?utm_campaign=in-app-help&amp;utm_medium=in-app-help&amp;utm_source=stash\""
                    + " target=\"_blank\">Documentation</a></li><li"
                    + " data-key=\"footer.links.jac\"><a "
                    + "href=\"https://jira.atlassian.com/browse/BSERV?utm_campaign=in-app-help&amp;utm_medium=in-app-help&amp;utm_source=stash\""
                    + " target=\"_blank\">Request a feature</a></li><li"
                    + " data-key=\"footer.links.about\"><a href=\"/about\">About</a></li><li"
                    + " data-key=\"footer.links.contact.atlassian\"><a href=\"https://www.atlassian"
                    + ".com/company/contact?utm_campaign=in-app-help&amp;utm_medium=in-app-help&amp;utm_source=stash\""
                    + " target=\"_blank\">Contact Atlassian</a></li></ul><div id=\"footer-logo\"><a"
                    + " href=\"https://www.atlassian.com/\""
                    + " target=\"_blank\">Atlassian</a></div></section></footer><!-- End #footer"
                    + " --></div><script>require('bitbucket/internal/layout/base/base').onReady(null,"
                    + " \"Bitbucket\" );"
                    + " require('bitbucket/internal/widget/keyboard-shortcuts/keyboard-shortcuts"
                    + "').onReady();</script><script>require('bitbucket/internal/page/global-repository-list/global-repository-list').init("
                    + " document.getElementById('repository-container'),{repositoryPage:"
                    + " {\"size\":1,\"limit\":25,"
                    + "\"isLastPage\":true,\"values\":[{\"slug\":\"tsunami-security-scanner-plugins\",\"id\":1,"
                    + "\"name\":\"tsunami-security-scanner-plugins\",\"hierarchyId\":\"b51e3a2c49ec92ab6d18\","
                    + "\"scmId\":\"git\",\"state\":\"AVAILABLE\",\"statusMessage\":\"Available\","
                    + "\"forkable\":true,\"project\":{\"key\":\"PUB\",\"id\":1,\"name\":\"public\","
                    + "\"public\":false,\"type\":\"NORMAL\",\"links\":{\"self\":[{\"href\":\"http://10.2.0"
                    + ".51:37990/projects/PUB\"}]},\"avatarUrl\":\"/projects/PUB/avatar"
                    + ".png?s=48&v=1659066041797\"},\"public\":true,\"archived\":false,"
                    + "\"links\":{\"clone\":[{\"href\":\"http://10.2.0"
                    + ".51:37990/scm/pub/tsunami-security-scanner-plugins.git\",\"name\":\"http\"},"
                    + "{\"href\":\"ssh://git@10.2.0.51:7999/pub/tsunami-security-scanner-plugins.git\","
                    + "\"name\":\"ssh\"}],\"self\":[{\"href\":\"http://10.2.0"
                    + ".51:37990/projects/PUB/repos/tsunami-security-scanner-plugins/browse\"}]}}],\"start\":0},"
                    + "});</script></body></html>"));
    mockWebServer.enqueue(
        new MockResponse().setResponseCode(HttpStatus.SERVICE_UNAVAILABLE.code()));

    mockCallbackServer.enqueue(PayloadTestHelper.generateMockSuccessfulCallbackResponse());

    TargetInfo targetInfo =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .build();

    DetectionReportList detectionReports = detector.detect(targetInfo, ImmutableList.of(service));

    assertThat(detectionReports.getDetectionReportsList())
        .containsExactly(
            DetectionReport.newBuilder()
                .setTargetInfo(targetInfo)
                .setNetworkService(service)
                .setDetectionTimestamp(
                    Timestamps.fromMillis(Instant.now(fakeUtcClock).toEpochMilli()))
                .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
                .setVulnerability(detector.getAdvisories().get(0))
                .build());
  }

  @Test
  public void detect_whenNotVulnerable_returnsnoVulnerability() throws IOException {
    mockWebServer.enqueue(
        new MockResponse()
            .setResponseCode(HttpStatus.OK.code())
            .setBody(
                "HTTP/1.1 200 \n"
                    + "X-AREQUESTID: @5BAAJ5x535x416x0\n"
                    + "x-xss-protection: 1; mode=block\n"
                    + "x-frame-options: SAMEORIGIN\n"
                    + "x-content-type-options: nosniff\n"
                    + "Pragma: no-cache\n"
                    + "Expires: Thu, 01 Jan 1970 00:00:00 GMT\n"
                    + "Cache-Control: no-cache\n"
                    + "Cache-Control: no-store\n"
                    + "vary: accept-encoding\n"
                    + "Content-Type: text/html;charset=UTF-8\n"
                    + "Content-Language: en-CA\n"
                    + "Date: Wed, 14 Sep 2022 08:55:59 GMT\n"
                    + "Connection: close\n"
                    + "Content-Length: 0\n"));
    mockWebServer.enqueue(
        new MockResponse().setResponseCode(HttpStatus.SERVICE_UNAVAILABLE.code()));

    mockCallbackServer.enqueue(PayloadTestHelper.generateMockUnsuccessfulCallbackResponse());

    TargetInfo targetInfo =
        TargetInfo.newBuilder()
            .addNetworkEndpoints(
                forHostnameAndPort(mockWebServer.getHostName(), mockWebServer.getPort()))
            .build();

    DetectionReportList detectionReports = detector.detect(targetInfo, ImmutableList.of(service));

    assertThat(detectionReports.getDetectionReportsList()).isEmpty();
  }
}
