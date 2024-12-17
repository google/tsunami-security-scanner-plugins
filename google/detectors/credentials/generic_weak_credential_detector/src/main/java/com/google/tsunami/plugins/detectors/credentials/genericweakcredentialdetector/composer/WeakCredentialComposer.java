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
package com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.composer;

import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.common.collect.Streams.stream;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Iterators;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.provider.TestCredential;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.tester.CredentialTester;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.testers.ncrack.NcrackCredentialTester;
import com.google.tsunami.proto.NetworkService;
import java.util.Iterator;
import java.util.List;

/**
 * Weak Credential Composer links generated {@link TestCredential}s with the {@link
 * CredentialTester}. Credentials are passed to the {@link CredentialTester} in batch mode to make
 * best use of credential tester that can reuse network connections, like {@link
 * NcrackCredentialTester} for instance. Batch mode also offers out of the box support for large
 * credentials databases that might not fit on the testing machine.
 */
public final class WeakCredentialComposer {

  private static final int DEFAULT_BATCH_SIZE = 100;
  private final int batchSize;
  private final ImmutableList<TestCredential> credentials;
  private final CredentialTester tester;

  @VisibleForTesting
  WeakCredentialComposer(
      ImmutableList<TestCredential> credentials, CredentialTester tester, int batchSize) {
    this.batchSize = batchSize;
    this.credentials = credentials;
    this.tester = tester;
  }

  public WeakCredentialComposer(
      ImmutableList<TestCredential> credentials, CredentialTester tester) {
    this(credentials, tester, DEFAULT_BATCH_SIZE);
  }

  /**
   * Batches the given test credentials to be tested by the {@link CredentialTester} and reports
   * valid {@link TestCredential}.
   *
   * @return List of valid {@link TestCredential}. An empty list is returned if no valid credentials
   *     are identified.
   */
  @CanIgnoreReturnValue
  public ImmutableList<TestCredential> run(NetworkService networkService) {
    if (!tester.canAccept(networkService)) {
      return ImmutableList.of();
    }

    if (tester.batched()) {
      Iterator<List<TestCredential>> credentialPartitions =
          Iterators.partition(credentials.iterator(), this.batchSize);

      return stream(credentialPartitions)
          .map(batchCredentials -> tester.testValidCredentials(networkService, batchCredentials))
          .flatMap(ImmutableList::stream)
          .collect(toImmutableList());
    }
    return tester.testValidCredentials(networkService, credentials);
  }
}
