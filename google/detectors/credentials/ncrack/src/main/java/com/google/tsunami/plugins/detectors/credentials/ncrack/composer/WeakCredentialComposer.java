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
package com.google.tsunami.plugins.detectors.credentials.ncrack.composer;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Iterators;
import com.google.common.collect.Streams;
import com.google.tsunami.plugins.detectors.credentials.ncrack.provider.CredentialProvider;
import com.google.tsunami.plugins.detectors.credentials.ncrack.provider.TestCredential;
import com.google.tsunami.plugins.detectors.credentials.ncrack.tester.CredentialTester;
import com.google.tsunami.proto.NetworkService;
import java.util.Iterator;
import java.util.List;

/**
 * Weak Credential Composer links the {@link CredentialProvider} generated test credentials with the
 * {@link CredentialTester}. Credentials are passed to the {@link CredentialTester} in batch mode to
 * make best use of credential tester that can reuse network connections, like {@link
 * com.google.tsunami.plugins.detectors.credentials.ncrack.NcrackCredentialTester} for
 * instance. Batch mode also offers out of the box support for large credentials databases that
 * might not fit on the testing machine.
 */
public final class WeakCredentialComposer {

  private static final int DEFAULT_BATCH_SIZE = 100;
  private final int batchSize;
  private final CredentialProvider provider;
  private final CredentialTester tester;

  @VisibleForTesting
  WeakCredentialComposer(CredentialProvider provider, CredentialTester tester, int batchSize) {
    this.batchSize = batchSize;
    this.provider = provider;
    this.tester = tester;
  }

  public WeakCredentialComposer(CredentialProvider provider, CredentialTester tester) {
    this(provider, tester, DEFAULT_BATCH_SIZE);
  }

  /**
   * Collects test credentials from {@link CredentialProvider} to be tested by the {@link
   * CredentialTester} and reports valid {@link TestCredential}.
   *
   * @return List of valid {@link TestCredential}. An empty list is returned if no valid credentials
   *     are identified.
   */
  public ImmutableList<TestCredential> run(NetworkService networkService) {
    if (!tester.canAccept(networkService)) {
      return ImmutableList.of();
    }

    Iterator<List<TestCredential>> credentialPartitions =
        Iterators.partition(provider.generateTestCredentials(), this.batchSize);

    return Streams.stream(credentialPartitions)
        .map(batchCredentials -> tester.testValidCredentials(networkService, batchCredentials))
        .flatMap(ImmutableList::stream)
        .collect(ImmutableList.toImmutableList());
  }
}
