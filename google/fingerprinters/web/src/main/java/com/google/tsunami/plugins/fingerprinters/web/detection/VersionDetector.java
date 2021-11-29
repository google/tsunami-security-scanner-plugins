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
package com.google.tsunami.plugins.fingerprinters.web.detection;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.tsunami.common.net.UrlUtils.removeLeadingSlashes;
import static com.google.tsunami.common.net.http.HttpMethod.GET;
import static com.google.tsunami.plugins.fingerprinters.web.common.CrawlUtils.buildCrawlResult;
import static com.google.tsunami.plugins.fingerprinters.web.common.FingerprintUtils.hashCrawlResult;
import static java.util.Comparator.comparing;
import static java.util.stream.Collectors.toCollection;
import static java.util.stream.Collectors.toMap;

import com.google.auto.value.AutoValue;
import com.google.common.base.Joiner;
import com.google.common.base.Strings;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Sets;
import com.google.common.flogger.GoogleLogger;
import com.google.inject.assistedinject.Assisted;
import com.google.tsunami.common.net.UrlUtils;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpRequest;
import com.google.tsunami.common.net.http.HttpResponse;
import com.google.tsunami.plugins.fingerprinters.web.data.FingerprintData;
import com.google.tsunami.plugins.fingerprinters.web.data.FingerprintRegistry;
import com.google.tsunami.plugins.fingerprinters.web.detection.SoftwareDetector.DetectedSoftware;
import com.google.tsunami.plugins.fingerprinters.web.proto.ContentHash;
import com.google.tsunami.plugins.fingerprinters.web.proto.Hash;
import com.google.tsunami.plugins.fingerprinters.web.proto.HashVersion;
import com.google.tsunami.plugins.fingerprinters.web.proto.PathVersion;
import com.google.tsunami.plugins.fingerprinters.web.proto.SoftwareIdentity;
import com.google.tsunami.plugins.fingerprinters.web.proto.Version;
import com.google.tsunami.plugins.fingerprinters.web.tools.MysqlUtil;
import com.google.tsunami.proto.CrawlResult;
import com.google.tsunami.proto.CrawlTarget;
import com.google.tsunami.proto.NetworkService;
import java.io.IOException;
import java.sql.SQLException;
import java.util.*;
import java.util.stream.Collectors;
import javax.inject.Inject;
import okhttp3.HttpUrl;

/** Identifies the potential software versions based on the crawled web content hashes. */
public final class VersionDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  /**
   * 检查潜在的版本信息
   * @param detectedSoftware
   * @return
   */
  public DetectedVersion detectVersions(DetectedSoftware detectedSoftware){

    Map<String,Integer> versions2count = MysqlUtil.getVersionsByPathAndHash(detectedSoftware.pathHashes());
    Map<String, Integer> sortedVersions2count = new LinkedHashMap<>();

    versions2count.entrySet().stream().filter(entry -> entry.getValue()>=3).sorted(Map.Entry.comparingByValue())
            .forEachOrdered(entry -> sortedVersions2count.put(entry.getKey(),entry.getValue()));

    //如果多个版本对应的命中数量一样，则返回多个
    ImmutableSet<Version> possibleVersions = new ImmutableSet.Builder<Version>().build();
    int currentMax = -1;
    for (Map.Entry<String, Integer> entry : sortedVersions2count.entrySet()){
      if (currentMax == -1) {
        currentMax = entry.getValue();
      }else{
       if (currentMax == entry.getValue())
         possibleVersions.add(Version.newBuilder().setFullName(entry.getKey()).build());
       else
         break;
      }
    }
    if(possibleVersions.size()==0){
      return null;
    }else {
      return DetectedVersion.builder()
              .setSoftwareIdentity(detectedSoftware.softwareIdentity())
              .setVersions(possibleVersions)
              .build();
    }
  }


  /** The version detection result. */
  @AutoValue
  public abstract static class DetectedVersion {
    public abstract SoftwareIdentity softwareIdentity();
    public abstract ImmutableSet<Version> versions();

    public static DetectedVersion newForUnknownVersion(SoftwareIdentity softwareIdentity) {
      return builder().setSoftwareIdentity(softwareIdentity).setVersions(ImmutableSet.of()).build();
    }

    public static Builder builder() {
      return new com.google.tsunami.plugins.fingerprinters.web.detection
          .AutoValue_VersionDetector_DetectedVersion.Builder();
    }

    /** Builder for {@link DetectedVersion}. */
    @AutoValue.Builder
    abstract static class Builder {
      public abstract Builder setSoftwareIdentity(SoftwareIdentity value);
      public abstract Builder setVersions(Collection<Version> value);

      public abstract DetectedVersion build();
    }
  }
}
