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
package com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.clients.ncrack.data;

import static com.google.common.base.Preconditions.checkNotNull;

import com.google.auto.value.AutoValue;
import com.google.common.collect.ImmutableList;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.clients.common.DiscoveredCredential;
import java.util.Collection;

/**
 * Ncrack brute force run results.
 *
 * <p>Ncrack output contains limited data and only the discovered credentials are of interest. XML
 * format has not been used as ncrack do not dump the identified credentials in the XML file.
 *
 * <p>NOTE: It is preferable in the future to switch to the XML format and use a DTD file maintained
 * by nrack to extract results.
 */
@AutoValue
public abstract class NcrackRun {
  public abstract ImmutableList<DiscoveredCredential> discoveredCredentials();

  public static NcrackRun create(Collection<DiscoveredCredential> discoveredCredentials) {
    checkNotNull(discoveredCredentials);
    return new AutoValue_NcrackRun(ImmutableList.copyOf(discoveredCredentials));
  }
}
