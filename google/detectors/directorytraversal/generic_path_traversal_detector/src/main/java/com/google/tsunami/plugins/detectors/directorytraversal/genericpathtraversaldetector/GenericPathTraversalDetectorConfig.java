/*
 * Copyright 2022 Google LLC
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
package com.google.tsunami.plugins.detectors.directorytraversal.genericpathtraversaldetector;

import com.google.auto.value.AutoValue;
import com.google.common.collect.ImmutableSet;

/** A configuration encapsulating InjectionPoints and request limits. */
@AutoValue
abstract class GenericPathTraversalDetectorConfig {
  abstract ImmutableSet<InjectionPoint> injectionPoints();

  abstract long maxCrawledUrlsToFuzz();

  abstract long maxExploitsToTest();

  abstract ImmutableSet<String> payloads();

  static GenericPathTraversalDetectorConfig create(
      ImmutableSet<InjectionPoint> injectingPoints,
      long maxCrawledUrlsToFuzz,
      long maxExploitsToTest,
      ImmutableSet<String> payloads) {
    return new AutoValue_GenericPathTraversalDetectorConfig(
        injectingPoints, maxCrawledUrlsToFuzz, maxExploitsToTest, payloads);
  }
}
