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
import static java.util.stream.Collectors.*;

import com.google.auto.value.AutoValue;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSetMultimap;
import com.google.common.flogger.GoogleLogger;
import com.google.tsunami.plugins.fingerprinters.web.proto.Hash;
import com.google.tsunami.plugins.fingerprinters.web.proto.SoftwareIdentity;
import com.google.tsunami.plugins.fingerprinters.web.tools.MysqlUtil;
import java.sql.SQLException;
import java.util.*;
import javax.inject.Inject;

/** Identifies the running software based on the crawled web contents. */
public final class SoftwareDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();


  private static Map<String,String> allPath2software;
  static {
    try {
      allPath2software = MysqlUtil.loadAllPath2Software();
    } catch (SQLException throwables) {
      logger.atSevere().log("获取所有路径对应软件的信息获取失败，失败原因%s",throwables.getMessage());
    }
  }

  /**
   * 判断是否有命中软件信息，如果没有命中直接返回空
   * @param path2hash
   * @return
   */
  public DetectedSoftware detectSoftware(ImmutableSetMultimap<String, Hash> path2hash) {
    logger.atInfo().log("Trying to detect potential software for the scan target.");
    //看一下路径对应的软件数量，如果只有唯一的软件名称或者有多个取最多的那个（并要求至少三个路径指向同一个软件）
    Map<String,Hash> detectedPathHash =  path2hash.entries().stream().
            filter(entry -> allPath2software.containsKey(entry.getKey())).
            collect(toMap((entry -> entry.getKey()),entry ->entry.getValue()));

    Map<String,Long> software2cnt = detectedPathHash.entrySet().stream().
            map(entry -> new AbstractMap.SimpleEntry<String,Long>(allPath2software.get(entry.getKey()),1l))
            .collect(groupingBy(AbstractMap.SimpleEntry::getKey,counting()));

    Optional<DetectedSoftware> detectedSoftware =  software2cnt.entrySet().stream().filter(entry -> entry.getValue()>=3l)
            .max(Map.Entry.comparingByValue()).map((software2MaxCnt) ->{
              return DetectedSoftware.builder().setSoftwareIdentity(SoftwareIdentity.newBuilder().setSoftware(software2MaxCnt.getKey()).build()).build();
            });
    return detectedSoftware.get();

  };



  /** The software detection result. */
  @AutoValue
  public abstract static class DetectedSoftware {
    public abstract SoftwareIdentity softwareIdentity();
    // Will be empty if rootPath not identified.
    public abstract String rootPath();
    public abstract ImmutableMap<String, Hash> pathHashes();

    public static Builder builder() {
      return new com.google.tsunami.plugins.fingerprinters.web.detection
          .AutoValue_SoftwareDetector_DetectedSoftware.Builder();
    }

    /** Builder for {@link DetectedSoftware}. */
    @AutoValue.Builder
    abstract static class Builder {
      public abstract Builder setSoftwareIdentity(SoftwareIdentity value);
      public abstract Builder setRootPath(String value);
      public abstract Builder setPathHashes(ImmutableMap<String, Hash> value);

      public abstract DetectedSoftware build();
    }
  }
}
