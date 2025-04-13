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
import com.google.tsunami.common.net.http.HttpResponse;

/**
 * A vulnerability detection containing information about the underlying exploit and its response.
 */
@AutoValue
abstract class Detection {
  abstract PotentialExploit exploit();

  abstract HttpResponse response();

  static Detection create(PotentialExploit exploit, HttpResponse response) {
    return new AutoValue_Detection(exploit, response);
  }

  @Override
  public final String toString() {
    return String.format(
        "Detection{exploit=%s, responseBody=%s, matchedRegex=%s}",
        this.exploit(), this.response().bodyString().get(), "root:x:0:0:");
  }
}
