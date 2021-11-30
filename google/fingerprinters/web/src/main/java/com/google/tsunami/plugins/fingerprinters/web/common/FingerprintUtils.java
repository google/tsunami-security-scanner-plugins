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
package com.google.tsunami.plugins.fingerprinters.web.common;

import static com.google.common.base.Preconditions.checkNotNull;

import com.google.common.hash.Hasher;
import com.google.common.hash.Hashing;
import com.google.tsunami.plugins.fingerprinters.web.proto.Hash;
import com.google.tsunami.proto.CrawlResult;

/** Utilities for calculating fingerprints from web applications. */
public final class FingerprintUtils {

  private FingerprintUtils() {}

  /**
   * Get the hash for a {@link CrawlResult} message.
   *
   * @param crawlResult the {@link CrawlResult} message to be hashed.
   * @return the hash for the {@link CrawlResult}.
   */
  public static Hash hashCrawlResult(CrawlResult crawlResult) {
    checkNotNull(crawlResult);
    Hasher hasher = Hashing.murmur3_128().newHasher();
    String hexHashCode =
        hasher
            .putInt(crawlResult.getResponseCode())
            .putBytes(crawlResult.getContentTypeBytes().toByteArray())
            .putBytes(crawlResult.getContent().toByteArray())
            .hash()
            .toString();
    return Hash.newBuilder().setHexString(hexHashCode).build();
  }

  /**
   * Get the hash for a blob of arbitrary data.
   *
   * @param content the data to be hashed.
   * @return the hash for the given data.
   */
  public static Hash hashBlob(byte[] content) {
    checkNotNull(content);
    return Hash.newBuilder()
        .setHexString(Hashing.murmur3_128().hashBytes(content).toString())
        .build();
  }
}
