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
package com.google.tsunami.plugins.fingerprinters.web.data;

import static com.google.common.base.Preconditions.checkNotNull;

import com.google.common.base.Stopwatch;
import com.google.common.collect.ImmutableMap;
import com.google.common.flogger.GoogleLogger;
import com.google.tsunami.common.reflection.RuntimeClassGraphScanResult;
import com.google.tsunami.plugins.fingerprinters.web.proto.Fingerprints;
import com.google.tsunami.plugins.fingerprinters.web.proto.SoftwareIdentity;
import io.github.classgraph.Resource;
import io.github.classgraph.ResourceList;
import io.github.classgraph.ScanResult;
import java.io.IOException;
import java.util.regex.Pattern;
import javax.inject.Inject;

/** A {@link FingerprintLoader} implementation that loads fingerprints data from resources. */
final class ResourceFingerprintLoader implements FingerprintLoader {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
  private static final Pattern FINGERPRINTS_RESOURCE_PATTERN =
      Pattern.compile(".*fingerprinters/web/data/.*\\.binproto");

  private final ScanResult scanResult;

  @Inject
  ResourceFingerprintLoader(@RuntimeClassGraphScanResult ScanResult scanResult) {
    this.scanResult = checkNotNull(scanResult);
  }

  @Override
  public ImmutableMap<SoftwareIdentity, FingerprintData> loadFingerprints() throws IOException {
    Stopwatch loadTimeStopwatch = Stopwatch.createStarted();

    ResourceList fingerprintsResources =
        scanResult.getResourcesMatchingPattern(FINGERPRINTS_RESOURCE_PATTERN);
    ImmutableMap.Builder<SoftwareIdentity, FingerprintData> fingerprintsBuilder =
        ImmutableMap.builder();
    for (Resource resource : fingerprintsResources) {
      logger.atInfo().log("Loading fingerprints from resource %s.", resource.getPath());
      Fingerprints fingerprints = Fingerprints.parseFrom(resource.load());
      fingerprintsBuilder.put(
          fingerprints.getSoftwareIdentity(), FingerprintData.fromProto(fingerprints));
    }

    ImmutableMap<SoftwareIdentity, FingerprintData> fingerprints = fingerprintsBuilder.build();
    logger.atInfo().log(
        "Finished loading %s web fingerprints data in %s.",
        fingerprints.size(), loadTimeStopwatch.stop());
    return fingerprints;
  }
}
