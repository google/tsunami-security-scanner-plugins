package com.google.tsunami.plugins.detectors.templateddetector.actions;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.inject.Guice;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.plugins.detectors.templateddetector.Environment;
import com.google.tsunami.proto.Hostname;
import com.google.tsunami.proto.NetworkEndpoint;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.Port;
import com.google.tsunami.proto.TransportProtocol;
import com.google.tsunami.templatedplugin.proto.HttpAction;
import com.google.tsunami.templatedplugin.proto.PluginAction;
import java.io.IOException;
import java.time.Instant;
import java.util.regex.PatternSyntaxException;
import javax.inject.Inject;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class HttpActionRunnerTest {
  private HttpActionRunner runner;
  private Environment environment;
  private MockWebServer mockWebServer;
  private NetworkService service;

  @Inject private HttpClient httpClient;

  private static final FakeUtcClock utcClock =
      FakeUtcClock.create().setNow(Instant.parse("2020-01-01T00:00:00.00Z"));

  @Before
  public void setup() {
    Guice.createInjector(new HttpClientModule.Builder().build()).injectMembers(this);
    this.runner = new HttpActionRunner(httpClient, false);
    this.environment = new Environment(false, utcClock);
  }

  @Before
  public void setupMockHttp() {
    this.mockWebServer = new MockWebServer();
    this.service =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                NetworkEndpoint.newBuilder()
                    .setHostname(Hostname.newBuilder().setName(this.mockWebServer.getHostName()))
                    .setType(NetworkEndpoint.Type.HOSTNAME_PORT)
                    .setPort(Port.newBuilder().setPortNumber(this.mockWebServer.getPort())))
            .setTransportProtocol(TransportProtocol.TCP)
            .build();
  }

  @After
  public void tearMockHttp() throws IOException {
    this.mockWebServer.shutdown();
  }

  @Test
  public void validRequestButNoConditions_returnsTrue() {
    PluginAction action =
        PluginAction.newBuilder()
            .setName("action")
            .setHttpRequest(
                HttpAction.newBuilder().setMethod(HttpAction.HttpMethod.GET).addUri("/"))
            .build();

    this.mockWebServer.enqueue(new MockResponse());

    assertThat(runner.run(this.service, action, this.environment)).isTrue();
    assertThat(this.mockWebServer.getRequestCount()).isEqualTo(1);
  }

  @Test
  public void notHttpAction_throwsIllegalArgumentException() {
    PluginAction action = PluginAction.newBuilder().setName("action").build();

    assertThrows(
        IllegalArgumentException.class, () -> runner.run(this.service, action, this.environment));
  }

  @Test
  public void invalidHttpMethod_throwsIllegalArgumentException() {
    PluginAction action =
        PluginAction.newBuilder()
            .setName("action")
            .setHttpRequest(
                HttpAction.newBuilder()
                    .setMethod(HttpAction.HttpMethod.METHOD_UNSPECIFIED)
                    .addUri("/"))
            .build();

    assertThrows(
        IllegalArgumentException.class, () -> runner.run(this.service, action, this.environment));
  }

  @Test
  public void setDataOnNonPost_throwsIllegalStateException() {
    PluginAction action =
        PluginAction.newBuilder()
            .setName("action")
            .setHttpRequest(
                HttpAction.newBuilder()
                    .setMethod(HttpAction.HttpMethod.GET)
                    .addUri("/")
                    .setData("data"))
            .build();

    assertThrows(
        IllegalStateException.class, () -> runner.run(this.service, action, this.environment));
  }

  @Test
  public void customHeader_headerInRequest() throws InterruptedException {
    PluginAction action =
        PluginAction.newBuilder()
            .setName("action")
            .setHttpRequest(
                HttpAction.newBuilder()
                    .setMethod(HttpAction.HttpMethod.GET)
                    .addUri("/")
                    .addHeaders(
                        HttpAction.HttpHeader.newBuilder()
                            .setName("Custom-Header")
                            .setValue("Custom-Value")))
            .build();

    this.mockWebServer.enqueue(new MockResponse());
    var result = runner.run(this.service, action, this.environment);
    RecordedRequest request = this.mockWebServer.takeRequest();

    assertThat(result).isTrue();
    assertThat(request.getHeader("Custom-Header")).isEqualTo("Custom-Value");
    assertThat(this.mockWebServer.getRequestCount()).isEqualTo(1);
  }

  @Test
  public void customHeaderWithSubstitution_headerInRequest() throws InterruptedException {
    PluginAction action =
        PluginAction.newBuilder()
            .setName("action")
            .setHttpRequest(
                HttpAction.newBuilder()
                    .setMethod(HttpAction.HttpMethod.GET)
                    .addUri("/")
                    .addHeaders(
                        HttpAction.HttpHeader.newBuilder()
                            .setName("Custom-Header")
                            .setValue("{{ envVariable }}")))
            .build();

    this.environment.set("envVariable", "Custom-Value");
    this.mockWebServer.enqueue(new MockResponse());
    var result = runner.run(this.service, action, this.environment);
    RecordedRequest request = this.mockWebServer.takeRequest();

    assertThat(result).isTrue();
    assertThat(request.getHeader("Custom-Header")).isEqualTo("Custom-Value");
    assertThat(this.mockWebServer.getRequestCount()).isEqualTo(1);
  }

  @Test
  public void postData_requestHasData() throws InterruptedException {
    PluginAction action =
        PluginAction.newBuilder()
            .setName("action")
            .setHttpRequest(
                HttpAction.newBuilder()
                    .setMethod(HttpAction.HttpMethod.POST)
                    .addUri("/")
                    .setData("someData"))
            .build();

    this.mockWebServer.enqueue(new MockResponse());
    var result = runner.run(this.service, action, this.environment);
    RecordedRequest request = this.mockWebServer.takeRequest();

    assertThat(result).isTrue();
    assertThat(request.getMethod()).isEqualTo("POST");
    assertThat(request.getUtf8Body()).isEqualTo("someData");
    assertThat(this.mockWebServer.getRequestCount()).isEqualTo(1);
  }

  @Test
  public void postDataWithSubstitution_requestHasData() throws InterruptedException {
    PluginAction action =
        PluginAction.newBuilder()
            .setName("action")
            .setHttpRequest(
                HttpAction.newBuilder()
                    .setMethod(HttpAction.HttpMethod.POST)
                    .addUri("/")
                    .setData("{{ envVariable }}"))
            .build();

    this.mockWebServer.enqueue(new MockResponse());
    this.environment.set("envVariable", "someData");
    var result = runner.run(this.service, action, this.environment);
    RecordedRequest request = this.mockWebServer.takeRequest();

    assertThat(result).isTrue();
    assertThat(request.getMethod()).isEqualTo("POST");
    assertThat(request.getUtf8Body()).isEqualTo("someData");
    assertThat(this.mockWebServer.getRequestCount()).isEqualTo(1);
  }

  @Test
  public void uriWithSubstitution_hasValidUri() throws InterruptedException {
    PluginAction action =
        PluginAction.newBuilder()
            .setName("action")
            .setHttpRequest(
                HttpAction.newBuilder()
                    .setMethod(HttpAction.HttpMethod.GET)
                    .addUri("/{{ envVariable }}"))
            .build();

    this.mockWebServer.enqueue(new MockResponse().setResponseCode(200));
    this.environment.set("envVariable", "index");
    var result = runner.run(this.service, action, this.environment);
    RecordedRequest request = this.mockWebServer.takeRequest();

    assertThat(result).isTrue();
    assertThat(request.getPath()).isEqualTo("/index");
    assertThat(this.mockWebServer.getRequestCount()).isEqualTo(1);
  }

  @Test
  public void multipleUris_runUntilOneSucceeds() throws InterruptedException {
    PluginAction action =
        PluginAction.newBuilder()
            .setName("action")
            .setHttpRequest(
                HttpAction.newBuilder()
                    .setMethod(HttpAction.HttpMethod.GET)
                    .addUri("/failure")
                    .addUri("/willSucceed")
                    .addUri("/notRun")
                    .setResponse(HttpAction.HttpResponse.newBuilder().setHttpStatus(200)))
            .build();

    this.mockWebServer.enqueue(new MockResponse().setResponseCode(404));
    this.mockWebServer.enqueue(new MockResponse().setResponseCode(200));
    var result = runner.run(this.service, action, this.environment);
    RecordedRequest request1 = this.mockWebServer.takeRequest();
    RecordedRequest request2 = this.mockWebServer.takeRequest();

    assertThat(result).isTrue();
    assertThat(request1.getPath()).isEqualTo("/failure");
    assertThat(request2.getPath()).isEqualTo("/willSucceed");
    assertThat(this.mockWebServer.getRequestCount()).isEqualTo(2);
  }

  @Test
  public void invalidStatusCode_returnsFalse() throws InterruptedException {
    PluginAction action =
        PluginAction.newBuilder()
            .setName("action")
            .setHttpRequest(
                HttpAction.newBuilder()
                    .setMethod(HttpAction.HttpMethod.GET)
                    .addUri("/")
                    .setResponse(HttpAction.HttpResponse.newBuilder().setHttpStatus(200)))
            .build();

    this.mockWebServer.enqueue(new MockResponse().setResponseCode(404));
    var result = runner.run(this.service, action, this.environment);

    assertThat(result).isFalse();
    assertThat(this.mockWebServer.getRequestCount()).isEqualTo(1);
  }

  @Test
  public void validStatusCode_returnsTrue() throws InterruptedException {
    PluginAction action =
        PluginAction.newBuilder()
            .setName("action")
            .setHttpRequest(
                HttpAction.newBuilder()
                    .setMethod(HttpAction.HttpMethod.GET)
                    .addUri("/")
                    .setResponse(HttpAction.HttpResponse.newBuilder().setHttpStatus(200)))
            .build();

    this.mockWebServer.enqueue(new MockResponse().setResponseCode(200));
    var result = runner.run(this.service, action, this.environment);

    assertThat(result).isTrue();
    assertThat(this.mockWebServer.getRequestCount()).isEqualTo(1);
  }

  @Test
  public void allExpectationsNotMet_returnsFalse() throws InterruptedException {
    PluginAction action =
        PluginAction.newBuilder()
            .setName("action")
            .setHttpRequest(
                HttpAction.newBuilder()
                    .setMethod(HttpAction.HttpMethod.GET)
                    .addUri("/")
                    .setResponse(
                        HttpAction.HttpResponse.newBuilder()
                            .setExpectAll(
                                HttpAction.HttpResponse.ExpectAll.newBuilder()
                                    .addConditions(
                                        HttpAction.HttpResponse.Expectation.newBuilder()
                                            .setContains("value1:true")
                                            .setBody(
                                                HttpAction.HttpResponse.Body.getDefaultInstance()))
                                    .addConditions(
                                        HttpAction.HttpResponse.Expectation.newBuilder()
                                            .setContains("value2:true")
                                            .setHeader(
                                                HttpAction.HttpResponse.Header.newBuilder()
                                                    .setName("custom-header")))
                                    .addConditions(
                                        HttpAction.HttpResponse.Expectation.newBuilder()
                                            .setContains("value3:true")
                                            .setBody(
                                                HttpAction.HttpResponse.Body
                                                    .getDefaultInstance())))))
            .build();

    this.mockWebServer.enqueue(
        new MockResponse()
            .setResponseCode(200)
            .setHeader("custom-header", "value2:false")
            .setBody("value1:true, value3:true"));
    var result = runner.run(this.service, action, this.environment);

    assertThat(result).isFalse();
    assertThat(this.mockWebServer.getRequestCount()).isEqualTo(1);
  }

  @Test
  public void allExpectationsMet_returnsTrue() throws InterruptedException {
    PluginAction action =
        PluginAction.newBuilder()
            .setName("action")
            .setHttpRequest(
                HttpAction.newBuilder()
                    .setMethod(HttpAction.HttpMethod.GET)
                    .addUri("/")
                    .setResponse(
                        HttpAction.HttpResponse.newBuilder()
                            .setExpectAll(
                                HttpAction.HttpResponse.ExpectAll.newBuilder()
                                    .addConditions(
                                        HttpAction.HttpResponse.Expectation.newBuilder()
                                            .setContains("value1:true")
                                            .setBody(
                                                HttpAction.HttpResponse.Body.getDefaultInstance()))
                                    .addConditions(
                                        HttpAction.HttpResponse.Expectation.newBuilder()
                                            .setContains("value2:true")
                                            .setHeader(
                                                HttpAction.HttpResponse.Header.newBuilder()
                                                    .setName("custom-header")))
                                    .addConditions(
                                        HttpAction.HttpResponse.Expectation.newBuilder()
                                            .setContains("value3:true")
                                            .setBody(
                                                HttpAction.HttpResponse.Body
                                                    .getDefaultInstance())))))
            .build();

    this.mockWebServer.enqueue(
        new MockResponse()
            .setResponseCode(200)
            .setHeader("custom-header", "value2:true")
            .setBody("value1:true, value3:true"));
    var result = runner.run(this.service, action, this.environment);

    assertThat(result).isTrue();
    assertThat(this.mockWebServer.getRequestCount()).isEqualTo(1);
  }

  @Test
  public void allExpectationsExpectationOneofNotSet_throwsException() {
    PluginAction action =
        PluginAction.newBuilder()
            .setName("action")
            .setHttpRequest(
                HttpAction.newBuilder()
                    .setMethod(HttpAction.HttpMethod.GET)
                    .addUri("/")
                    .setResponse(
                        HttpAction.HttpResponse.newBuilder()
                            .setExpectAll(
                                HttpAction.HttpResponse.ExpectAll.newBuilder()
                                    .addConditions(
                                        HttpAction.HttpResponse.Expectation.newBuilder()
                                            .setContains("value1:true")))))
            .build();

    this.mockWebServer.enqueue(new MockResponse().setResponseCode(200));

    assertThrows(
        IllegalArgumentException.class, () -> runner.run(this.service, action, this.environment));
  }

  @Test
  public void allExpectationsWithSubstitution_returnsTrue() {
    PluginAction action =
        PluginAction.newBuilder()
            .setName("action")
            .setHttpRequest(
                HttpAction.newBuilder()
                    .setMethod(HttpAction.HttpMethod.GET)
                    .addUri("/")
                    .setResponse(
                        HttpAction.HttpResponse.newBuilder()
                            .setExpectAll(
                                HttpAction.HttpResponse.ExpectAll.newBuilder()
                                    .addConditions(
                                        HttpAction.HttpResponse.Expectation.newBuilder()
                                            .setContains("value1:{{ expValue1 }}")
                                            .setBody(
                                                HttpAction.HttpResponse.Body.getDefaultInstance()))
                                    .addConditions(
                                        HttpAction.HttpResponse.Expectation.newBuilder()
                                            .setContains("value2:{{ expValue2 }}")
                                            .setHeader(
                                                HttpAction.HttpResponse.Header.newBuilder()
                                                    .setName("{{ expHeaderName }}")))
                                    .addConditions(
                                        HttpAction.HttpResponse.Expectation.newBuilder()
                                            .setContains("value3:true")
                                            .setBody(
                                                HttpAction.HttpResponse.Body
                                                    .getDefaultInstance())))))
            .build();

    this.mockWebServer.enqueue(
        new MockResponse()
            .setResponseCode(200)
            .setHeader("custom-header", "value2:true")
            .setBody("value1:true, value3:true"));
    this.environment.set("expValue1", "true");
    this.environment.set("expValue2", "true");
    this.environment.set("expHeaderName", "custom-header");
    var result = runner.run(this.service, action, this.environment);

    assertThat(result).isTrue();
    assertThat(this.mockWebServer.getRequestCount()).isEqualTo(1);
  }

  @Test
  public void anyExpectationsNotMet_returnsFalse() throws InterruptedException {
    PluginAction action =
        PluginAction.newBuilder()
            .setName("action")
            .setHttpRequest(
                HttpAction.newBuilder()
                    .setMethod(HttpAction.HttpMethod.GET)
                    .addUri("/")
                    .setResponse(
                        HttpAction.HttpResponse.newBuilder()
                            .setExpectAny(
                                HttpAction.HttpResponse.ExpectAny.newBuilder()
                                    .addConditions(
                                        HttpAction.HttpResponse.Expectation.newBuilder()
                                            .setContains("value1:true")
                                            .setBody(
                                                HttpAction.HttpResponse.Body.getDefaultInstance()))
                                    .addConditions(
                                        HttpAction.HttpResponse.Expectation.newBuilder()
                                            .setContains("value2:true")
                                            .setHeader(
                                                HttpAction.HttpResponse.Header.newBuilder()
                                                    .setName("custom-header")))
                                    .addConditions(
                                        HttpAction.HttpResponse.Expectation.newBuilder()
                                            .setContains("value3:true")
                                            .setBody(
                                                HttpAction.HttpResponse.Body
                                                    .getDefaultInstance())))))
            .build();

    this.mockWebServer.enqueue(
        new MockResponse()
            .setResponseCode(200)
            .setHeader("custom-header", "value2:false")
            .setBody("value1:false, value3:false"));
    var result = runner.run(this.service, action, this.environment);

    assertThat(result).isFalse();
    assertThat(this.mockWebServer.getRequestCount()).isEqualTo(1);
  }

  @Test
  public void anyExpectationsMet_returnsTrue() throws InterruptedException {
    PluginAction action =
        PluginAction.newBuilder()
            .setName("action")
            .setHttpRequest(
                HttpAction.newBuilder()
                    .setMethod(HttpAction.HttpMethod.GET)
                    .addUri("/")
                    .setResponse(
                        HttpAction.HttpResponse.newBuilder()
                            .setExpectAny(
                                HttpAction.HttpResponse.ExpectAny.newBuilder()
                                    .addConditions(
                                        HttpAction.HttpResponse.Expectation.newBuilder()
                                            .setContains("value1:true")
                                            .setBody(
                                                HttpAction.HttpResponse.Body.getDefaultInstance()))
                                    .addConditions(
                                        HttpAction.HttpResponse.Expectation.newBuilder()
                                            .setContains("value2:true")
                                            .setHeader(
                                                HttpAction.HttpResponse.Header.newBuilder()
                                                    .setName("custom-header")))
                                    .addConditions(
                                        HttpAction.HttpResponse.Expectation.newBuilder()
                                            .setContains("value3:true")
                                            .setBody(
                                                HttpAction.HttpResponse.Body
                                                    .getDefaultInstance())))))
            .build();

    this.mockWebServer.enqueue(
        new MockResponse()
            .setResponseCode(200)
            .setHeader("custom-header", "value2:true")
            .setBody("value1:false, value3:false"));
    var result = runner.run(this.service, action, this.environment);

    assertThat(result).isTrue();
    assertThat(this.mockWebServer.getRequestCount()).isEqualTo(1);
  }

  @Test
  public void anyExpectationsExpectationOneofNotSet_throwsException() {
    PluginAction action =
        PluginAction.newBuilder()
            .setName("action")
            .setHttpRequest(
                HttpAction.newBuilder()
                    .setMethod(HttpAction.HttpMethod.GET)
                    .addUri("/")
                    .setResponse(
                        HttpAction.HttpResponse.newBuilder()
                            .setExpectAny(
                                HttpAction.HttpResponse.ExpectAny.newBuilder()
                                    .addConditions(
                                        HttpAction.HttpResponse.Expectation.newBuilder()
                                            .setContains("value1:true")))))
            .build();

    this.mockWebServer.enqueue(new MockResponse().setResponseCode(200));

    assertThrows(
        IllegalArgumentException.class, () -> runner.run(this.service, action, this.environment));
  }

  @Test
  public void anyExpectationsWithSubstitution_returnsTrue() throws InterruptedException {
    PluginAction action =
        PluginAction.newBuilder()
            .setName("action")
            .setHttpRequest(
                HttpAction.newBuilder()
                    .setMethod(HttpAction.HttpMethod.GET)
                    .addUri("/")
                    .setResponse(
                        HttpAction.HttpResponse.newBuilder()
                            .setExpectAny(
                                HttpAction.HttpResponse.ExpectAny.newBuilder()
                                    .addConditions(
                                        HttpAction.HttpResponse.Expectation.newBuilder()
                                            .setContains("{{ expValue1 }}:true")
                                            .setBody(
                                                HttpAction.HttpResponse.Body.getDefaultInstance()))
                                    .addConditions(
                                        HttpAction.HttpResponse.Expectation.newBuilder()
                                            .setContains("{{ expValue2 }}:true")
                                            .setHeader(
                                                HttpAction.HttpResponse.Header.newBuilder()
                                                    .setName("{{ expHeaderName }}")))
                                    .addConditions(
                                        HttpAction.HttpResponse.Expectation.newBuilder()
                                            .setContains("value3:true")
                                            .setBody(
                                                HttpAction.HttpResponse.Body
                                                    .getDefaultInstance())))))
            .build();

    this.mockWebServer.enqueue(
        new MockResponse()
            .setResponseCode(200)
            .setHeader("custom-header", "value2:true")
            .setBody("value1:false, value3:false"));
    this.environment.set("expValue1", "value1");
    this.environment.set("expValue2", "value2");
    this.environment.set("expHeaderName", "custom-header");
    var result = runner.run(this.service, action, this.environment);

    assertThat(result).isTrue();
    assertThat(this.mockWebServer.getRequestCount()).isEqualTo(1);
  }

  @Test
  public void allExtractionsNoMatches_returnsFalseButPartiallySetsEnv()
      throws InterruptedException {
    PluginAction action =
        PluginAction.newBuilder()
            .setName("action")
            .setHttpRequest(
                HttpAction.newBuilder()
                    .setMethod(HttpAction.HttpMethod.GET)
                    .addUri("/")
                    .setResponse(
                        HttpAction.HttpResponse.newBuilder()
                            .setExtractAll(
                                HttpAction.HttpResponse.ExtractAll.newBuilder()
                                    .addPatterns(
                                        HttpAction.HttpResponse.Extract.newBuilder()
                                            .setVariableName("var1")
                                            .setRegexp("value1:([a-z]+)")
                                            .setFromBody(
                                                HttpAction.HttpResponse.Body.getDefaultInstance()))
                                    .addPatterns(
                                        HttpAction.HttpResponse.Extract.newBuilder()
                                            .setVariableName("var2")
                                            .setRegexp("value2:([a-z]+)")
                                            .setFromHeader(
                                                HttpAction.HttpResponse.Header.newBuilder()
                                                    .setName("custom-header")))
                                    .addPatterns(
                                        HttpAction.HttpResponse.Extract.newBuilder()
                                            .setVariableName("var3")
                                            .setRegexp("value3:([a-z]+)")
                                            .setFromBody(
                                                HttpAction.HttpResponse.Body
                                                    .getDefaultInstance())))))
            .build();

    this.mockWebServer.enqueue(
        new MockResponse()
            .setResponseCode(200)
            .setHeader("custom-header", "no match")
            .setBody("value1:false, value3:true"));
    var result = runner.run(this.service, action, this.environment);

    assertThat(result).isFalse();
    assertThat(this.environment.get("var1")).isEqualTo("false");
    assertThat(this.environment.get("var2")).isNull();
    assertThat(this.environment.get("var3")).isNull();
    assertThat(this.mockWebServer.getRequestCount()).isEqualTo(1);
  }

  @Test
  public void allExtractionsMatches_returnsTrueAndSetsEnv() throws InterruptedException {
    PluginAction action =
        PluginAction.newBuilder()
            .setName("action")
            .setHttpRequest(
                HttpAction.newBuilder()
                    .setMethod(HttpAction.HttpMethod.GET)
                    .addUri("/")
                    .setResponse(
                        HttpAction.HttpResponse.newBuilder()
                            .setExtractAll(
                                HttpAction.HttpResponse.ExtractAll.newBuilder()
                                    .addPatterns(
                                        HttpAction.HttpResponse.Extract.newBuilder()
                                            .setVariableName("var1")
                                            .setRegexp("value1:([a-z]+)")
                                            .setFromBody(
                                                HttpAction.HttpResponse.Body.getDefaultInstance()))
                                    .addPatterns(
                                        HttpAction.HttpResponse.Extract.newBuilder()
                                            .setVariableName("var2")
                                            .setRegexp("value2:([a-z]+)")
                                            .setFromHeader(
                                                HttpAction.HttpResponse.Header.newBuilder()
                                                    .setName("custom-header")))
                                    .addPatterns(
                                        HttpAction.HttpResponse.Extract.newBuilder()
                                            .setVariableName("var3")
                                            .setRegexp("value3:([a-z]+)")
                                            .setFromBody(
                                                HttpAction.HttpResponse.Body
                                                    .getDefaultInstance())))))
            .build();

    this.mockWebServer.enqueue(
        new MockResponse()
            .setResponseCode(200)
            .setHeader("custom-header", "value2:something")
            .setBody("value1:false, value3:true"));
    var result = runner.run(this.service, action, this.environment);

    assertThat(result).isTrue();
    assertThat(this.environment.get("var1")).isEqualTo("false");
    assertThat(this.environment.get("var2")).isEqualTo("something");
    assertThat(this.environment.get("var3")).isEqualTo("true");
    assertThat(this.mockWebServer.getRequestCount()).isEqualTo(1);
  }

  @Test
  public void allExtractionsExtractOneofNotSet_throwsException() throws InterruptedException {
    PluginAction action =
        PluginAction.newBuilder()
            .setName("action")
            .setHttpRequest(
                HttpAction.newBuilder()
                    .setMethod(HttpAction.HttpMethod.GET)
                    .addUri("/")
                    .setResponse(
                        HttpAction.HttpResponse.newBuilder()
                            .setExtractAll(
                                HttpAction.HttpResponse.ExtractAll.newBuilder()
                                    .addPatterns(
                                        HttpAction.HttpResponse.Extract.newBuilder()
                                            .setVariableName("var1")
                                            .setRegexp("value1:([a-z]+)")))))
            .build();

    this.mockWebServer.enqueue(new MockResponse().setResponseCode(200));

    assertThrows(
        IllegalArgumentException.class, () -> runner.run(this.service, action, this.environment));
  }

  @Test
  public void allExtractionsWithSubstitution_returnsTrueAndSetsEnv() throws InterruptedException {
    PluginAction action =
        PluginAction.newBuilder()
            .setName("action")
            .setHttpRequest(
                HttpAction.newBuilder()
                    .setMethod(HttpAction.HttpMethod.GET)
                    .addUri("/")
                    .setResponse(
                        HttpAction.HttpResponse.newBuilder()
                            .setExtractAll(
                                HttpAction.HttpResponse.ExtractAll.newBuilder()
                                    .addPatterns(
                                        HttpAction.HttpResponse.Extract.newBuilder()
                                            .setVariableName("var1")
                                            .setRegexp("{{ expValue1Name }}:([a-z]+)")
                                            .setFromBody(
                                                HttpAction.HttpResponse.Body.getDefaultInstance()))
                                    .addPatterns(
                                        HttpAction.HttpResponse.Extract.newBuilder()
                                            .setVariableName("var2")
                                            .setRegexp("{{ expValue2Name }}:([a-z]+)")
                                            .setFromHeader(
                                                HttpAction.HttpResponse.Header.newBuilder()
                                                    .setName("{{ expHeaderName }}")))
                                    .addPatterns(
                                        HttpAction.HttpResponse.Extract.newBuilder()
                                            .setVariableName("var3")
                                            .setRegexp("value3:([a-z]+)")
                                            .setFromBody(
                                                HttpAction.HttpResponse.Body
                                                    .getDefaultInstance())))))
            .build();

    this.mockWebServer.enqueue(
        new MockResponse()
            .setResponseCode(200)
            .setHeader("custom-header", "value2:something")
            .setBody("value1:false, value3:true"));
    this.environment.set("expValue1Name", "value1");
    this.environment.set("expValue2Name", "value2");
    this.environment.set("expHeaderName", "custom-header");
    var result = runner.run(this.service, action, this.environment);

    assertThat(result).isTrue();
    assertThat(this.environment.get("var1")).isEqualTo("false");
    assertThat(this.environment.get("var2")).isEqualTo("something");
    assertThat(this.environment.get("var3")).isEqualTo("true");
    assertThat(this.mockWebServer.getRequestCount()).isEqualTo(1);
  }

  @Test
  public void anyExtractionsNoMatches_returnsFalse() throws InterruptedException {
    PluginAction action =
        PluginAction.newBuilder()
            .setName("action")
            .setHttpRequest(
                HttpAction.newBuilder()
                    .setMethod(HttpAction.HttpMethod.GET)
                    .addUri("/")
                    .setResponse(
                        HttpAction.HttpResponse.newBuilder()
                            .setExtractAny(
                                HttpAction.HttpResponse.ExtractAny.newBuilder()
                                    .addPatterns(
                                        HttpAction.HttpResponse.Extract.newBuilder()
                                            .setVariableName("var1")
                                            .setRegexp("value1:([a-z]+)")
                                            .setFromBody(
                                                HttpAction.HttpResponse.Body.getDefaultInstance()))
                                    .addPatterns(
                                        HttpAction.HttpResponse.Extract.newBuilder()
                                            .setVariableName("var2")
                                            .setRegexp("value2:([a-z]+)")
                                            .setFromHeader(
                                                HttpAction.HttpResponse.Header.newBuilder()
                                                    .setName("custom-header")))
                                    .addPatterns(
                                        HttpAction.HttpResponse.Extract.newBuilder()
                                            .setVariableName("var3")
                                            .setRegexp("value3:([a-z]+)")
                                            .setFromBody(
                                                HttpAction.HttpResponse.Body
                                                    .getDefaultInstance())))))
            .build();

    this.mockWebServer.enqueue(
        new MockResponse()
            .setResponseCode(200)
            .setHeader("custom-header", "no match")
            .setBody("no pattern match"));
    var result = runner.run(this.service, action, this.environment);

    assertThat(result).isFalse();
    assertThat(this.environment.get("var1")).isNull();
    assertThat(this.environment.get("var2")).isNull();
    assertThat(this.environment.get("var3")).isNull();
    assertThat(this.mockWebServer.getRequestCount()).isEqualTo(1);
  }

  @Test
  public void anyExtractionsMatches_returnsTrueAndSetsEnv() throws InterruptedException {
    PluginAction action =
        PluginAction.newBuilder()
            .setName("action")
            .setHttpRequest(
                HttpAction.newBuilder()
                    .setMethod(HttpAction.HttpMethod.GET)
                    .addUri("/")
                    .setResponse(
                        HttpAction.HttpResponse.newBuilder()
                            .setExtractAny(
                                HttpAction.HttpResponse.ExtractAny.newBuilder()
                                    .addPatterns(
                                        HttpAction.HttpResponse.Extract.newBuilder()
                                            .setVariableName("var1")
                                            .setRegexp("value1:([a-z]+)")
                                            .setFromBody(
                                                HttpAction.HttpResponse.Body.getDefaultInstance()))
                                    .addPatterns(
                                        HttpAction.HttpResponse.Extract.newBuilder()
                                            .setVariableName("var2")
                                            .setRegexp("value2:([a-z]+)")
                                            .setFromHeader(
                                                HttpAction.HttpResponse.Header.newBuilder()
                                                    .setName("custom-header")))
                                    .addPatterns(
                                        HttpAction.HttpResponse.Extract.newBuilder()
                                            .setVariableName("var3")
                                            .setRegexp("value3:([a-z]+)")
                                            .setFromBody(
                                                HttpAction.HttpResponse.Body
                                                    .getDefaultInstance())))))
            .build();

    this.mockWebServer.enqueue(
        new MockResponse()
            .setResponseCode(200)
            .setHeader("custom-header", "value2:true")
            .setBody("only the second pattern value2:true matches"));
    var result = runner.run(this.service, action, this.environment);

    assertThat(result).isTrue();
    assertThat(this.environment.get("var1")).isNull();
    assertThat(this.environment.get("var2")).isEqualTo("true");
    assertThat(this.environment.get("var3")).isNull();
    assertThat(this.mockWebServer.getRequestCount()).isEqualTo(1);
  }

  @Test
  public void anyExtractionsExtractOneofNotSet_throwsException() throws InterruptedException {
    PluginAction action =
        PluginAction.newBuilder()
            .setName("action")
            .setHttpRequest(
                HttpAction.newBuilder()
                    .setMethod(HttpAction.HttpMethod.GET)
                    .addUri("/")
                    .setResponse(
                        HttpAction.HttpResponse.newBuilder()
                            .setExtractAny(
                                HttpAction.HttpResponse.ExtractAny.newBuilder()
                                    .addPatterns(
                                        HttpAction.HttpResponse.Extract.newBuilder()
                                            .setVariableName("var1")
                                            .setRegexp("value1:([a-z]+)")))))
            .build();

    this.mockWebServer.enqueue(new MockResponse().setResponseCode(200));

    assertThrows(
        IllegalArgumentException.class, () -> runner.run(this.service, action, this.environment));
  }

  @Test
  public void anyExtractionsWithSubstitution_returnsTrueAndSetsEnv() throws InterruptedException {
    PluginAction action =
        PluginAction.newBuilder()
            .setName("action")
            .setHttpRequest(
                HttpAction.newBuilder()
                    .setMethod(HttpAction.HttpMethod.GET)
                    .addUri("/")
                    .setResponse(
                        HttpAction.HttpResponse.newBuilder()
                            .setExtractAny(
                                HttpAction.HttpResponse.ExtractAny.newBuilder()
                                    .addPatterns(
                                        HttpAction.HttpResponse.Extract.newBuilder()
                                            .setVariableName("var1")
                                            .setRegexp("{{ expValue1Name }}:([a-z]+)")
                                            .setFromBody(
                                                HttpAction.HttpResponse.Body.getDefaultInstance()))
                                    .addPatterns(
                                        HttpAction.HttpResponse.Extract.newBuilder()
                                            .setVariableName("var2")
                                            .setRegexp("{{ expValue2Name }}:([a-z]+)")
                                            .setFromHeader(
                                                HttpAction.HttpResponse.Header.newBuilder()
                                                    .setName("{{ expHeaderName }}")))
                                    .addPatterns(
                                        HttpAction.HttpResponse.Extract.newBuilder()
                                            .setVariableName("var3")
                                            .setRegexp("value3:([a-z]+)")
                                            .setFromBody(
                                                HttpAction.HttpResponse.Body
                                                    .getDefaultInstance())))))
            .build();

    this.mockWebServer.enqueue(
        new MockResponse()
            .setResponseCode(200)
            .setHeader("custom-header", "value2:true")
            .setBody("only the second pattern value2:true matches"));
    this.environment.set("expValue1Name", "value1");
    this.environment.set("expValue2Name", "value2");
    this.environment.set("expHeaderName", "custom-header");
    var result = runner.run(this.service, action, this.environment);

    assertThat(result).isTrue();
    assertThat(this.environment.get("var1")).isNull();
    assertThat(this.environment.get("var2")).isEqualTo("true");
    assertThat(this.environment.get("var3")).isNull();
    assertThat(this.mockWebServer.getRequestCount()).isEqualTo(1);
  }

  @Test
  public void extractionWithInvalidRegexp_throwsPatternSyntaxException() {
    PluginAction action =
        PluginAction.newBuilder()
            .setName("action")
            .setHttpRequest(
                HttpAction.newBuilder()
                    .setMethod(HttpAction.HttpMethod.GET)
                    .addUri("/")
                    .setResponse(
                        HttpAction.HttpResponse.newBuilder()
                            .setExtractAny(
                                HttpAction.HttpResponse.ExtractAny.newBuilder()
                                    .addPatterns(
                                        HttpAction.HttpResponse.Extract.newBuilder()
                                            .setVariableName("var1")
                                            .setRegexp("value1:([a-z]+")
                                            .setFromBody(
                                                HttpAction.HttpResponse.Body
                                                    .getDefaultInstance())))))
            .build();

    this.mockWebServer.enqueue(new MockResponse().setResponseCode(200));

    assertThrows(
        PatternSyntaxException.class, () -> runner.run(this.service, action, this.environment));
  }
}
