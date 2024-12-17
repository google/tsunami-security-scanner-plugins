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
package com.google.tsunami.plugins.fingerprinters.web;

import com.google.protobuf.ByteString;
import com.google.tsunami.plugins.fingerprinters.web.data.FingerprintData;
import com.google.tsunami.plugins.fingerprinters.web.proto.ContentHash;
import com.google.tsunami.plugins.fingerprinters.web.proto.Fingerprints;
import com.google.tsunami.plugins.fingerprinters.web.proto.Hash;
import com.google.tsunami.plugins.fingerprinters.web.proto.HashVersion;
import com.google.tsunami.plugins.fingerprinters.web.proto.PathVersion;
import com.google.tsunami.plugins.fingerprinters.web.proto.SoftwareIdentity;
import com.google.tsunami.plugins.fingerprinters.web.proto.Version;
import com.google.tsunami.proto.CrawlResult;
import com.google.tsunami.proto.CrawlTarget;
import okhttp3.HttpUrl;

/** Common test data for web fingerprinter and its dependencies. */
public final class CommonTestData {

  private CommonTestData() {}

  public static final CrawlResult COMMON_LIB =
      CrawlResult.newBuilder()
          .setCrawlTarget(
              CrawlTarget.newBuilder().setUrl(fakeUrl("/common/lib.js")).setHttpMethod("GET"))
          .setResponseCode(200)
          .setContent(ByteString.copyFromUtf8("common lib"))
          .build();
  public static final Hash COMMON_LIB_HASH =
      Hash.newBuilder().setHexString("62085acfe76fb812e785e1a090822702").build();
  public static final CrawlResult SOFTWARE_1_JQUERY =
      CrawlResult.newBuilder()
          .setCrawlTarget(
              CrawlTarget.newBuilder().setUrl(fakeUrl("/software1/jquery.js")).setHttpMethod("GET"))
          .setResponseCode(200)
          .setContent(ByteString.copyFromUtf8("common jquery"))
          .build();
  public static final CrawlResult SOFTWARE_2_JQUERY =
      CrawlResult.newBuilder()
          .setCrawlTarget(
              CrawlTarget.newBuilder().setUrl(fakeUrl("/software2/jquery.js")).setHttpMethod("GET"))
          .setResponseCode(200)
          .setContent(ByteString.copyFromUtf8("common jquery"))
          .build();
  public static final Hash JQUERY_HASH =
      Hash.newBuilder().setHexString("5e714c99e915764097979e4dbc894649").build();
  public static final CrawlResult SOFTWARE_1_CSS =
      CrawlResult.newBuilder()
          .setCrawlTarget(
              CrawlTarget.newBuilder().setUrl(fakeUrl("/software1/m.css")).setHttpMethod("GET"))
          .setResponseCode(200)
          .setContent(ByteString.copyFromUtf8("software1 css"))
          .build();
  public static final Hash SOFTWARE_1_CSS_HASH =
      Hash.newBuilder().setHexString("c5aceac5962782ca2279eb12e5de037d").build();
  public static final CrawlResult SOFTWARE_1_ICON =
      CrawlResult.newBuilder()
          .setCrawlTarget(
              CrawlTarget.newBuilder().setUrl(fakeUrl("/icon.png")).setHttpMethod("GET"))
          .setResponseCode(200)
          .setContent(ByteString.copyFromUtf8("software1 icon"))
          .build();
  public static final Hash SOFTWARE_1_ICON_HASH =
      Hash.newBuilder().setHexString("58009671cb1993e149c68d489c84177f").build();
  public static final CrawlResult SOFTWARE_2_CSS =
      CrawlResult.newBuilder()
          .setCrawlTarget(
              CrawlTarget.newBuilder()
                  .setUrl(fakeUrl("/software2/m.css?v=2.0"))
                  .setHttpMethod("GET"))
          .setResponseCode(200)
          .setContent(ByteString.copyFromUtf8("software2 css"))
          .build();
  public static final CrawlResult SOFTWARE_2_CSS_NEW_PATH =
      CrawlResult.newBuilder()
          .setCrawlTarget(
              CrawlTarget.newBuilder()
                  .setUrl(fakeUrl("/software2/m.css?v=2.1"))
                  .setHttpMethod("GET"))
          .setResponseCode(200)
          .setContent(ByteString.copyFromUtf8("software2 css"))
          .build();
  public static final CrawlResult SOFTWARE_2_CSS_UNKNOWN_VERSION_PATH =
      CrawlResult.newBuilder()
          .setCrawlTarget(
              CrawlTarget.newBuilder()
                  .setUrl(fakeUrl("/software2/m.css?v=unknown"))
                  .setHttpMethod("GET"))
          .setResponseCode(200)
          .setContent(ByteString.copyFromUtf8("software2 css"))
          .build();
  public static final Hash SOFTWARE_2_CSS_HASH =
      Hash.newBuilder().setHexString("d21502f4f80814bcb98f8dd204eecc89").build();
  public static final CrawlResult SOFTWARE_2_ICON =
      CrawlResult.newBuilder()
          .setCrawlTarget(
              CrawlTarget.newBuilder().setUrl(fakeUrl("/icon.png")).setHttpMethod("GET"))
          .setResponseCode(200)
          .setContent(ByteString.copyFromUtf8("software2 icon"))
          .build();
  public static final Hash SOFTWARE_2_ICON_HASH =
      Hash.newBuilder().setHexString("0e8493d8ddaf39774968c19a77ad4825").build();
  public static final CrawlResult SOFTWARE_3_ZIP =
      CrawlResult.newBuilder()
          .setCrawlTarget(
              CrawlTarget.newBuilder().setUrl(fakeUrl("/file.zip")).setHttpMethod("GET"))
          .setResponseCode(200)
          .setContentType("application/zip")
          .setContent(ByteString.copyFromUtf8("software3 zip with contents"))
          .build();
  public static final Hash SOFTWARE_3_ZIP_HASH =
      Hash.newBuilder().setHexString("57c793cbc96ed671d01d76b0b3ff8630").build();

  public static final CrawlResult SOFTWARE_3_CSS =
      CrawlResult.newBuilder()
          .setCrawlTarget(
              CrawlTarget.newBuilder().setUrl(fakeUrl("/file.css")).setHttpMethod("GET"))
          .setResponseCode(200)
          .setContentType("text/css")
          .setContent(
              ByteString.copyFromUtf8(
                  ".materialize-red{background-color:#e51c23"
                      + " !important}.materialize-red-text{color:#e51c23"
                      + " !important}.materialize-red.lighten-5{background-color:#fdeaeb"
                      + " !important}.materialize-red-text.text-lighten-5{color:#fdeaeb"
                      + " !important}.materialize-red.lighten-4{background-color:#f8c1c3"
                      + " !important}.materialize-red-text.text-lighten-4{color:#f8c1c3"
                      + " !important}.materialize-red.lighten-3{background-color:#f3989b"
                      + " !important}.materialize-red-text.text-lighten-3{color:#f3989b"
                      + " !important}.materialize-red.lighten-2{background-color:#ee6e73."))
          .build();
  public static final Hash SOFTWARE_3_CSS_HASH =
      Hash.newBuilder().setHexString("1ebae34d06fc5a9be81b852a7c354041").build();

  public static final CrawlResult SOFTWARE_4_MLFLOW =
      CrawlResult.newBuilder()
          .setCrawlTarget(
              CrawlTarget.newBuilder().setUrl(fakeUrl("/login?from")).setHttpMethod("GET"))
          .setResponseCode(200)
          .setContent(ByteString.copyFromUtf8("MLFLOW"))
          .build();

  public static final CrawlResult UNKNOWN_CONTENT =
      CrawlResult.newBuilder()
          .setCrawlTarget(CrawlTarget.newBuilder().setUrl(fakeUrl("/unknown")).setHttpMethod("GET"))
          .setResponseCode(200)
          .setContent(ByteString.copyFromUtf8("unknown"))
          .build();
  public static final SoftwareIdentity SOFTWARE_IDENTITY_1 =
      SoftwareIdentity.newBuilder().setSoftware("Software1").build();
  public static final SoftwareIdentity SOFTWARE_IDENTITY_2 =
      SoftwareIdentity.newBuilder().setSoftware("Software2").build();
  public static final SoftwareIdentity SOFTWARE_IDENTITY_3 =
      SoftwareIdentity.newBuilder().setSoftware("Software3").build();

  public static final SoftwareIdentity SOFTWARE_IDENTITY_4 =
      SoftwareIdentity.newBuilder().setSoftware("mlflow").build();
  public static final FingerprintData FINGERPRINT_DATA_1 =
      FingerprintData.fromProto(
          Fingerprints.newBuilder()
              .setSoftwareIdentity(SOFTWARE_IDENTITY_1)
              .addContentHashes(
                  ContentHash.newBuilder()
                      .setContentPath(getPath(COMMON_LIB.getCrawlTarget().getUrl()))
                      .addHashes(COMMON_LIB_HASH))
              .addContentHashes(
                  ContentHash.newBuilder()
                      .setContentPath(getPath(SOFTWARE_1_JQUERY.getCrawlTarget().getUrl()))
                      .addHashes(JQUERY_HASH))
              .addContentHashes(
                  ContentHash.newBuilder()
                      .setContentPath(getPath(SOFTWARE_1_CSS.getCrawlTarget().getUrl()))
                      .addHashes(SOFTWARE_1_CSS_HASH))
              .addContentHashes(
                  ContentHash.newBuilder()
                      .setContentPath(getPath(SOFTWARE_1_ICON.getCrawlTarget().getUrl()))
                      .addHashes(SOFTWARE_1_ICON_HASH))
              .addHashVersions(
                  HashVersion.newBuilder()
                      .setHash(COMMON_LIB_HASH)
                      .addVersions(Version.newBuilder().setFullName("1.0"))
                      .addVersions(Version.newBuilder().setFullName("1.1"))
                      .addVersions(Version.newBuilder().setFullName("1.2"))
                      .addVersions(Version.newBuilder().setFullName("1.3")))
              .addHashVersions(
                  HashVersion.newBuilder()
                      .setHash(JQUERY_HASH)
                      .addVersions(Version.newBuilder().setFullName("1.0"))
                      .addVersions(Version.newBuilder().setFullName("1.1"))
                      .addVersions(Version.newBuilder().setFullName("1.2")))
              .addHashVersions(
                  HashVersion.newBuilder()
                      .setHash(SOFTWARE_1_CSS_HASH)
                      .addVersions(Version.newBuilder().setFullName("1.2"))
                      .addVersions(Version.newBuilder().setFullName("1.3")))
              .addHashVersions(
                  HashVersion.newBuilder()
                      .setHash(SOFTWARE_1_ICON_HASH)
                      .addVersions(Version.newBuilder().setFullName("1.0")))
              .build());
  public static final FingerprintData FINGERPRINT_DATA_2 =
      FingerprintData.fromProto(
          Fingerprints.newBuilder()
              .setSoftwareIdentity(SOFTWARE_IDENTITY_2)
              .addContentHashes(
                  ContentHash.newBuilder()
                      .setContentPath(getPath(COMMON_LIB.getCrawlTarget().getUrl()))
                      .addHashes(COMMON_LIB_HASH))
              .addContentHashes(
                  ContentHash.newBuilder()
                      .setContentPath(getPath(SOFTWARE_2_JQUERY.getCrawlTarget().getUrl()))
                      .addHashes(JQUERY_HASH))
              .addContentHashes(
                  ContentHash.newBuilder()
                      .setContentPath(getPath(SOFTWARE_2_CSS.getCrawlTarget().getUrl()))
                      .addHashes(SOFTWARE_2_CSS_HASH))
              .addContentHashes(
                  ContentHash.newBuilder()
                      .setContentPath(getPath(SOFTWARE_2_CSS_NEW_PATH.getCrawlTarget().getUrl()))
                      .addHashes(SOFTWARE_2_CSS_HASH))
              .addContentHashes(
                  ContentHash.newBuilder()
                      .setContentPath(getPath(SOFTWARE_2_ICON.getCrawlTarget().getUrl()))
                      .addHashes(SOFTWARE_2_ICON_HASH))
              .addHashVersions(
                  HashVersion.newBuilder()
                      .setHash(COMMON_LIB_HASH)
                      .addVersions(Version.newBuilder().setFullName("2.0"))
                      .addVersions(Version.newBuilder().setFullName("2.1"))
                      .addVersions(Version.newBuilder().setFullName("2.2")))
              .addHashVersions(
                  HashVersion.newBuilder()
                      .setHash(JQUERY_HASH)
                      .addVersions(Version.newBuilder().setFullName("2.0"))
                      .addVersions(Version.newBuilder().setFullName("2.1"))
                      .addVersions(Version.newBuilder().setFullName("2.2")))
              .addHashVersions(
                  HashVersion.newBuilder()
                      .setHash(SOFTWARE_2_CSS_HASH)
                      .addVersions(Version.newBuilder().setFullName("2.0"))
                      .addVersions(Version.newBuilder().setFullName("2.1")))
              .addHashVersions(
                  HashVersion.newBuilder()
                      .setHash(SOFTWARE_2_ICON_HASH)
                      .addVersions(Version.newBuilder().setFullName("2.0"))
                      .addVersions(Version.newBuilder().setFullName("2.1")))
              .addPathVersions(
                  PathVersion.newBuilder()
                      .setContentPath(getPath(COMMON_LIB.getCrawlTarget().getUrl()))
                      .addVersions(Version.newBuilder().setFullName("2.0"))
                      .addVersions(Version.newBuilder().setFullName("2.1"))
                      .addVersions(Version.newBuilder().setFullName("2.2")))
              .addPathVersions(
                  PathVersion.newBuilder()
                      .setContentPath(getPath(SOFTWARE_2_JQUERY.getCrawlTarget().getUrl()))
                      .addVersions(Version.newBuilder().setFullName("2.0"))
                      .addVersions(Version.newBuilder().setFullName("2.1"))
                      .addVersions(Version.newBuilder().setFullName("2.2")))
              .addPathVersions(
                  PathVersion.newBuilder()
                      .setContentPath(getPath(SOFTWARE_2_CSS.getCrawlTarget().getUrl()))
                      .addVersions(Version.newBuilder().setFullName("2.0")))
              .addPathVersions(
                  PathVersion.newBuilder()
                      .setContentPath(getPath(SOFTWARE_2_CSS_NEW_PATH.getCrawlTarget().getUrl()))
                      .addVersions(Version.newBuilder().setFullName("2.1")))
              .addPathVersions(
                  PathVersion.newBuilder()
                      .setContentPath(getPath(SOFTWARE_2_ICON.getCrawlTarget().getUrl()))
                      .addVersions(Version.newBuilder().setFullName("2.0"))
                      .addVersions(Version.newBuilder().setFullName("2.1")))
              .build());

  public static final FingerprintData FINGERPRINT_DATA_3 =
      FingerprintData.fromProto(
          Fingerprints.newBuilder()
              .setSoftwareIdentity(SOFTWARE_IDENTITY_3)
              .addContentHashes(
                  ContentHash.newBuilder()
                      .setContentPath(getPath(SOFTWARE_3_ZIP.getCrawlTarget().getUrl()))
                      .addHashes(SOFTWARE_3_ZIP_HASH))
              .addContentHashes(
                  ContentHash.newBuilder()
                      .setContentPath(getPath(SOFTWARE_3_CSS.getCrawlTarget().getUrl()))
                      .addHashes(SOFTWARE_3_CSS_HASH))
              .addHashVersions(
                  HashVersion.newBuilder()
                      .setHash(SOFTWARE_3_ZIP_HASH)
                      .addVersions(Version.newBuilder().setFullName("2.0"))
                      .addVersions(Version.newBuilder().setFullName("2.1")))
              .addHashVersions(
                  HashVersion.newBuilder()
                      .setHash(SOFTWARE_3_CSS_HASH)
                      .addVersions(Version.newBuilder().setFullName("2.1")))
              .build());

  public static String fakeUrl(String path) {
    return new HttpUrl.Builder().scheme("https").host("localhost").encodedPath(path).toString();
  }

  public static String getPath(String url) {
    return HttpUrl.get(url).encodedPath().substring(1);
  }
}
