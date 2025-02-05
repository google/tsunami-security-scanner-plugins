package com.google.tsunami.plugins.detectors.templateddetector;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.inject.Guice;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpClientModule;
import com.google.tsunami.plugin.TcsClient;
import com.google.tsunami.plugin.payload.PayloadSecretGenerator;
import com.google.tsunami.plugin.payload.testing.FakePayloadGeneratorModule;
import com.google.tsunami.proto.Hostname;
import com.google.tsunami.proto.IpAddress;
import com.google.tsunami.proto.NetworkEndpoint;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.Port;
import com.google.tsunami.proto.TransportProtocol;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.regex.PatternSyntaxException;
import javax.inject.Inject;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class EnvironmentTest {
  private static final SecureRandom testSecureRandom =
      new SecureRandom() {
        @Override
        public void nextBytes(byte[] bytes) {
          Arrays.fill(bytes, (byte) 0xFF);
        }
      };

  @Inject private HttpClient httpClient;
  @Inject private PayloadSecretGenerator secretGenerator;

  @Before
  public void setup() {
    Guice.createInjector(
        new HttpClientModule.Builder().build(),
        FakePayloadGeneratorModule.builder()
                .setSecureRng(testSecureRandom)
                .build())
        .injectMembers(this);
  }

  @Test
  public void initializeWithCallback_setsEnvironment() {
    TcsClient tcsClient = new TcsClient("1.2.3.4", 1234, "http://polling/", httpClient);

    NetworkService networkService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                NetworkEndpoint.newBuilder()
                    .setIpAddress(IpAddress.newBuilder().setAddress("127.0.0.1"))
                    .setHostname(Hostname.newBuilder().setName("hostname"))
                    .setType(NetworkEndpoint.Type.HOSTNAME_PORT)
                    .setPort(Port.newBuilder().setPortNumber(80)))
            .setTransportProtocol(TransportProtocol.TCP)
            .build();
    Environment env = new Environment(false);
    env.initializeFor(networkService, tcsClient, secretGenerator);

    assertThat(env.get("T_NS_BASEURL")).isEqualTo("http://hostname:80/");
    assertThat(env.get("T_NS_PROTOCOL")).isEqualTo("TCP");
    assertThat(env.get("T_NS_HOSTNAME")).isEqualTo("hostname");
    assertThat(env.get("T_NS_PORT")).isEqualTo("80");
    assertThat(env.get("T_NS_IP")).isEqualTo("127.0.0.1");
    assertThat(env.get("T_CBS_URI")).isEqualTo("http://1.2.3.4:1234/2f2f44946531433a8eec636344578b3e6a321a52ff328315f446dfe0");
    assertThat(env.get("T_CBS_ADDRESS")).isEqualTo("1.2.3.4");
    assertThat(env.get("T_CBS_PORT")).isEqualTo("1234");
    assertThat(env.get("T_CBS_SECRET")).isEqualTo("ffffffffffffffff");
  }
  
  @Test
  public void initializeWithoutCallbackButWithSecrets_setsEnvironment() {
    TcsClient tcsClient = new TcsClient("", 0, "", httpClient);

    NetworkService networkService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                NetworkEndpoint.newBuilder()
                    .setIpAddress(IpAddress.newBuilder().setAddress("127.0.0.1"))
                    .setHostname(Hostname.newBuilder().setName("hostname"))
                    .setType(NetworkEndpoint.Type.HOSTNAME_PORT)
                    .setPort(Port.newBuilder().setPortNumber(80)))
            .setTransportProtocol(TransportProtocol.TCP)
            .build();
    Environment env = new Environment(false);
    env.initializeFor(networkService, tcsClient, secretGenerator);

    assertThat(env.get("T_NS_BASEURL")).isEqualTo("http://hostname:80/");
    assertThat(env.get("T_NS_PROTOCOL")).isEqualTo("TCP");
    assertThat(env.get("T_NS_HOSTNAME")).isEqualTo("hostname");
    assertThat(env.get("T_NS_PORT")).isEqualTo("80");
    assertThat(env.get("T_NS_IP")).isEqualTo("127.0.0.1");
    assertThat(env.get("T_CBS_SECRET")).isEqualTo("ffffffffffffffff");
    assertThat(env.get("T_CBS_URI")).isNull();
    assertThat(env.get("T_CBS_ADDRESS")).isNull();
    assertThat(env.get("T_CBS_PORT")).isNull();
  }

  @Test
  public void initializeWithoutCallback_setsEnvironment() {
    TcsClient tcsClient = new TcsClient("", 0, "", httpClient);

    NetworkService networkService =
        NetworkService.newBuilder()
            .setNetworkEndpoint(
                NetworkEndpoint.newBuilder()
                    .setIpAddress(IpAddress.newBuilder().setAddress("127.0.0.1"))
                    .setHostname(Hostname.newBuilder().setName("hostname"))
                    .setType(NetworkEndpoint.Type.HOSTNAME_PORT)
                    .setPort(Port.newBuilder().setPortNumber(80)))
            .setTransportProtocol(TransportProtocol.TCP)
            .build();
    Environment env = new Environment(false);
    env.initializeFor(networkService, tcsClient, null);

    assertThat(env.get("T_NS_BASEURL")).isEqualTo("http://hostname:80/");
    assertThat(env.get("T_NS_PROTOCOL")).isEqualTo("TCP");
    assertThat(env.get("T_NS_HOSTNAME")).isEqualTo("hostname");
    assertThat(env.get("T_NS_PORT")).isEqualTo("80");
    assertThat(env.get("T_NS_IP")).isEqualTo("127.0.0.1");
    assertThat(env.get("T_CBS_SECRET")).isNull();
    assertThat(env.get("T_CBS_URI")).isNull();
    assertThat(env.get("T_CBS_ADDRESS")).isNull();
    assertThat(env.get("T_CBS_PORT")).isNull();
  }

  @Test
  public void setVariable_addsToEnvironment() {
    Environment env = new Environment(false);
    env.set("var1", "value1");
    env.set("var2", "value2");

    assertThat(env.get("var1")).isEqualTo("value1");
    assertThat(env.get("var2")).isEqualTo("value2");
  }

  @Test
  public void substitute_replacesVariablesInTemplate() {
    Environment env = new Environment(false);
    env.set("var1", "value1");
    env.set("var2", "value2");

    // Note the difference in spacing and var3 not being set.
    String template = "This is {{ var1 }}.{{var2}} and this is {{ var3 }}.{{ var2 }}";
    String expected = "This is value1.{{var2}} and this is {{ var3 }}.value2";

    assertThat(env.substitute(template)).isEqualTo(expected);
  }

  @Test
  public void substituteWithInvalidTemplate_replacesNothing() {
    Environment env = new Environment(false);
    env.set("var1", "value1");

    String template = "This is {var1}";
    String expected = "This is {var1}";

    assertThat(env.substitute(template)).isEqualTo(expected);
  }

  @Test
  public void substituteWithNonExistingVar_replacesNothing() {
    Environment env = new Environment(false);
    env.set("var2", "value2");

    String template = "This is {{var1}}{{ var1 }}";
    String expected = "This is {{var1}}{{ var1 }}";

    assertThat(env.substitute(template)).isEqualTo(expected);
  }

  @Test
  public void extractWhenFound_addsToEnvironment() {
    Environment env = new Environment(false);

    String template = "value1:12345";
    String pattern = "value1:([0-9]+)";

    assertThat(env.extract(template, "var1", pattern)).isTrue();
    assertThat(env.get("var1")).isEqualTo("12345");
  }

  @Test
  public void extractWhenNotFound_returnsFalse() {
    Environment env = new Environment(false);

    String template = "value1:abcdef";
    String pattern = "value1:([0-9]+)";

    assertThat(env.extract(template, "var1", pattern)).isFalse();
    assertThat(env.get("var1")).isNull();
  }

  @Test
  public void extractWhenInvalidPattern_throwsException() {
    Environment env = new Environment(false);

    String template = "value1:abcdef";
    String pattern = "value1:([0-9]+";

    assertThrows(PatternSyntaxException.class, () -> env.extract(template, "var1", pattern));
  }
}
