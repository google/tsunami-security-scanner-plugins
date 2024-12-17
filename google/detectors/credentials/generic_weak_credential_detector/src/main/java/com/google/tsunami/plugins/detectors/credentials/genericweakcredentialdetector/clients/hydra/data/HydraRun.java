/*
 * Copyright 2023 Google LLC
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
package com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.clients.hydra.data;

import static com.google.common.base.Preconditions.checkNotNull;

import com.google.auto.value.AutoValue;
import com.google.common.collect.ImmutableList;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.clients.common.DiscoveredCredential;
import java.util.Collection;

/**
 * Hydra brute force run results.
 *
 * <p>Hydra output contains limited data and only the discovered credentials are of interest.
 */
@AutoValue
public abstract class HydraRun {
  public abstract ImmutableList<DiscoveredCredential> discoveredCredentials();

  public static HydraRun create(Collection<DiscoveredCredential> discoveredCredentials) {
    checkNotNull(discoveredCredentials);
    return new AutoValue_HydraRun(ImmutableList.copyOf(discoveredCredentials));
  }
}
