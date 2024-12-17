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
package com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.tester;

import com.google.common.collect.ImmutableList;
import com.google.tsunami.plugins.detectors.credentials.genericweakcredentialdetector.provider.TestCredential;
import com.google.tsunami.proto.NetworkService;
import java.util.List;

/**
 * Credential testers are in charge of testing valid credentials against provided service.
 *
 * <p>Credential testers provide an {@code canAccept} method to indicate if it supports the provided
 * service. {@code canAccept} must called before the {@code testValidCredentials}.
 */
public abstract class CredentialTester {

  public abstract String name();

  public abstract String description();

  /** Indicates if the current provider can test the specified service. */
  public abstract boolean canAccept(NetworkService networkService);

  /** Indicates if testing should be performaed in the batched mode. */
  public abstract boolean batched();

  /**
   * Tests a set of credentials against provided service.
   *
   * <p>The method accepts of a list of credentials to enable efficient support of bulk testing;
   * this applies for external tools that can perform connection reuse or other protocol specific
   * tricks.
   *
   * <p>While the method is expected to return the list of all valid credentials, it is expected
   * that some tester will return after identifying the first valid credential.
   *
   * <p>The method must throw an {@link UnsupportedTargetOrServiceException} if it doesn't support
   * the provided service.
   *
   * @return List of all valid credentials detected during testing.
   */
  public abstract ImmutableList<TestCredential> testValidCredentials(
      NetworkService networkService, List<TestCredential> credentials);
}
